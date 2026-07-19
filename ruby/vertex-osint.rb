#!/usr/bin/env ruby
# ═══════════════════════════════════════════════════════════════
#  VERTEX-OSINT — Ruby Intelligence Gathering Engine
#  crt.sh subdomain enum, tech fingerprint, header analysis,
#  WHOIS/ASN correlation, Wayback snapshots, report generation
# ═══════════════════════════════════════════════════════════════

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'socket'
require 'time'
require 'fileutils'

module Colors
  RED    = "\e[0;31m"
  GREEN  = "\e[0;32m"
  YELLOW = "\e[1;33m"
  CYAN   = "\e[0;36m"
  PURPLE = "\e[0;35m"
  BOLD   = "\e[1m"
  RST    = "\e[0m"
end

include Colors

class VertexOSINT
  REPORT_DIR = File.expand_path("~/vertex-recon-logs/osint")
  
  # Known CDN/WAF signatures
  WAF_SIGNATURES = {
    'cloudflare'    => /cloudflare/i,
    'akamai'        => /akamai|ghost/i,
    'aws-cloudfront'=> /cloudfront/i,
    'fastly'        => /fastly/i,
    'incapsula'     => /incapsula|imperva/i,
    'sucuri'        => /sucuri/i,
    'aws-alb'       => /awselb/i,
    'varnish'       => /varnish/i,
    'nginx'         => /nginx/i,
    'apache'        => /apache/i,
    'iis'           => /microsoft-iis/i,
    'litespeed'     => /litespeed/i,
  }

  # Tech detection patterns in headers and HTML
  TECH_PATTERNS = {
    'WordPress'   => [/wp-content|wp-includes|wordpress/i, :body],
    'React'       => [/__next|react|_next\/static/i, :body],
    'Vue.js'      => [/vue\.js|vuejs/i, :body],
    'jQuery'      => [/jquery/i, :body],
    'Bootstrap'   => [/bootstrap/i, :body],
    'PHP'         => [/x-powered-by:.*php/i, :header],
    'ASP.NET'     => [/x-powered-by:.*asp|x-aspnet/i, :header],
    'Express'     => [/x-powered-by:.*express/i, :header],
    'Django'      => [/csrfmiddlewaretoken|django/i, :body],
    'Laravel'     => [/laravel_session|XSRF-TOKEN/i, :header],
    'Next.js'     => [/_next\/|__next/i, :body],
    'Vercel'      => [/x-vercel|vercel/i, :header],
    'Netlify'     => [/x-nf-request|netlify/i, :header],
    'Cloudflare Pages' => [/cf-ray/i, :header],
  }

  def initialize(domain)
    @domain = domain.gsub(/^https?:\/\//, '').gsub(/\/.*/, '')
    @findings = { subdomains: [], technologies: [], headers: {}, 
                  dns: {}, certificates: [], wayback: [], whois: {} }
    FileUtils.mkdir_p(REPORT_DIR)
  end

  # ─── crt.sh subdomain enumeration ────────────────────────────

  def enumerate_subdomains
    section("SUBDOMAIN ENUMERATION (crt.sh)")
    
    uri = URI("https://crt.sh/?q=%25.#{@domain}&output=json")
    response = safe_get(uri)
    return unless response

    begin
      certs = JSON.parse(response.body)
      subdomains = certs
        .map { |c| c['name_value'] }
        .compact
        .flat_map { |n| n.split("\n") }
        .map { |s| s.strip.downcase.gsub(/^\*\./, '') }
        .uniq
        .sort

      @findings[:subdomains] = subdomains
      
      info "Found #{subdomains.length} unique subdomains"
      subdomains.each_with_index do |sub, i|
        # Resolve each one
        begin
          ips = Socket.getaddrinfo(sub, nil, :INET)
                      .map { |a| a[3] }.uniq
          status = ips.empty? ? "#{RED}NXDOMAIN#{RST}" : "#{GREEN}#{ips.join(', ')}#{RST}"
        rescue
          status = "#{YELLOW}unresolvable#{RST}"
        end
        finding "#{sub} → #{status}"
        break if i > 50 # cap output
      end
      
      if subdomains.length > 50
        info "... and #{subdomains.length - 50} more (see report)"
      end
    rescue JSON::ParserError
      warn "Failed to parse crt.sh response"
    end
  end

  # ─── HTTP header & security analysis ─────────────────────────

  def analyze_headers
    section("HTTP SECURITY HEADERS")
    
    uri = URI("https://#{@domain}")
    response = safe_get(uri, redirect: false)
    return unless response

    headers = {}
    response.each_header { |k, v| headers[k.downcase] = v }
    @findings[:headers] = headers

    security_headers = {
      'strict-transport-security' => { critical: true, desc: 'HSTS' },
      'content-security-policy'   => { critical: true, desc: 'CSP' },
      'x-frame-options'           => { critical: true, desc: 'Clickjack protection' },
      'x-content-type-options'    => { critical: true, desc: 'MIME sniffing prevention' },
      'x-xss-protection'          => { critical: false, desc: 'XSS filter' },
      'referrer-policy'           => { critical: false, desc: 'Referrer control' },
      'permissions-policy'        => { critical: false, desc: 'Feature permissions' },
      'cross-origin-opener-policy'=> { critical: false, desc: 'COOP' },
      'cross-origin-resource-policy' => { critical: false, desc: 'CORP' },
    }

    score = 0
    max_score = security_headers.length

    security_headers.each do |name, meta|
      if headers[name]
        ok "#{meta[:desc]} (#{name}): #{truncate(headers[name], 60)}"
        score += 1
      else
        severity = meta[:critical] ? RED : YELLOW
        tag = meta[:critical] ? "CRITICAL-MISSING" : "MISSING"
        puts "  #{severity}[!]#{RST} #{meta[:desc]} (#{name}): #{tag}"
      end
    end

    grade = case (score.to_f / max_score * 100).round
            when 80..100 then "#{GREEN}A#{RST}"
            when 60..79  then "#{YELLOW}B#{RST}"
            when 40..59  then "#{YELLOW}C#{RST}"
            when 20..39  then "#{RED}D#{RST}"
            else "#{RED}F#{RST}"
            end

    puts "\n  #{BOLD}Security Score:#{RST} #{score}/#{max_score} — Grade: #{grade}"

    # Info leak check
    puts "\n  #{BOLD}Information Leakage:#{RST}"
    leak_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
    leak_headers.each do |h|
      warn "#{h}: #{headers[h]}" if headers[h]
    end

    # Cookie security
    if headers['set-cookie']
      puts "\n  #{BOLD}Cookie Analysis:#{RST}"
      cookies = headers['set-cookie']
      has_secure = cookies.downcase.include?('secure')
      has_httponly = cookies.downcase.include?('httponly')
      has_samesite = cookies.downcase.include?('samesite')
      
      has_secure ? ok("Secure flag set") : warn("Missing Secure flag")
      has_httponly ? ok("HttpOnly flag set") : warn("Missing HttpOnly flag")
      has_samesite ? ok("SameSite set") : warn("Missing SameSite attribute")
    end
  end

  # ─── Technology fingerprinting ───────────────────────────────

  def fingerprint_tech
    section("TECHNOLOGY FINGERPRINT")
    
    uri = URI("https://#{@domain}")
    response = safe_get(uri)
    return unless response

    body = response.body.to_s
    header_str = ""
    response.each_header { |k, v| header_str += "#{k}: #{v}\n" }

    detected = []

    # WAF/CDN detection
    WAF_SIGNATURES.each do |name, pattern|
      if header_str.match?(pattern) || body.match?(pattern)
        detected << { type: 'WAF/CDN', name: name }
      end
    end

    # Tech stack detection
    TECH_PATTERNS.each do |name, (pattern, source)|
      target = source == :header ? header_str : body
      if target.match?(pattern)
        detected << { type: 'Framework', name: name }
      end
    end

    # Meta generator tag
    if body =~ /meta[^>]+generator[^>]+content="([^"]+)"/i
      detected << { type: 'Generator', name: $1 }
    end

    @findings[:technologies] = detected

    detected.each do |tech|
      finding "#{tech[:type]}: #{CYAN}#{tech[:name]}#{RST}"
    end

    ok("#{detected.length} technologies detected") if detected.any?
  end

  # ─── TLS/Certificate analysis ────────────────────────────────

  def analyze_tls
    section("TLS/CERTIFICATE ANALYSIS")
    
    begin
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      
      tcp = TCPSocket.new(@domain, 443)
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = @domain
      ssl.connect

      cert = ssl.peer_cert
      chain = ssl.peer_cert_chain

      puts "  #{BOLD}Protocol:#{RST}    #{ssl.ssl_version}"
      puts "  #{BOLD}Cipher:#{RST}      #{ssl.cipher[0]} (#{ssl.cipher[2]} bit)"
      puts "  #{BOLD}Subject:#{RST}     #{cert.subject}"
      puts "  #{BOLD}Issuer:#{RST}      #{cert.issuer}"
      puts "  #{BOLD}Serial:#{RST}      #{cert.serial}"
      puts "  #{BOLD}Not Before:#{RST}  #{cert.not_before}"
      puts "  #{BOLD}Not After:#{RST}   #{cert.not_after}"

      # SANs
      san_ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
      if san_ext
        sans = san_ext.value.split(',').map(&:strip)
        puts "  #{BOLD}SANs:#{RST}        #{sans.length} entries"
        sans.each { |s| puts "    #{s}" }
      end

      # Expiry check
      days_left = ((cert.not_after - Time.now) / 86400).to_i
      if days_left < 0
        warn "Certificate EXPIRED #{days_left.abs} days ago!"
      elsif days_left < 30
        warn "Certificate expires in #{days_left} days"
      else
        ok "Certificate valid for #{days_left} more days"
      end

      # Chain
      puts "\n  #{BOLD}Certificate Chain:#{RST}"
      chain&.each_with_index do |c, i|
        puts "    #{i}: #{c.subject}"
      end

      # Key details
      key = cert.public_key
      puts "\n  #{BOLD}Public Key:#{RST}  #{key.class.name.split('::').last} #{key.respond_to?(:n) ? key.n.num_bits : 'EC'} bit"

      @findings[:certificates] = [{
        subject: cert.subject.to_s,
        issuer: cert.issuer.to_s,
        not_after: cert.not_after.to_s,
        sans: sans || [],
        days_left: days_left
      }]

      ssl.close
      tcp.close
    rescue => e
      warn "TLS analysis failed: #{e.message}"
    end
  end

  # ─── Wayback Machine snapshots ───────────────────────────────

  def wayback_check
    section("WAYBACK MACHINE HISTORY")
    
    uri = URI("https://web.archive.org/cdx/search/cdx?url=#{@domain}/*&output=json&limit=20&fl=timestamp,original,statuscode,mimetype")
    response = safe_get(uri)
    return unless response

    begin
      data = JSON.parse(response.body)
      return if data.length <= 1 # header only

      info "#{data.length - 1} snapshots found (showing last 20)"
      data[1..].each do |row|
        ts, url, status, mime = row
        date = "#{ts[0..3]}-#{ts[4..5]}-#{ts[6..7]}"
        finding "#{date} [#{status}] #{truncate(url, 60)} (#{mime})"
      end
      
      @findings[:wayback] = data[1..].map { |r| { date: r[0], url: r[1], status: r[2] } }
    rescue
      warn "Failed to parse Wayback response"
    end
  end

  # ─── IP/ASN lookup ───────────────────────────────────────────

  def ip_intel
    section("IP INTELLIGENCE")

    begin
      ips = Socket.getaddrinfo(@domain, nil, :INET).map { |a| a[3] }.uniq
      
      ips.each do |ip|
        uri = URI("https://ipinfo.io/#{ip}/json")
        response = safe_get(uri)
        next unless response

        data = JSON.parse(response.body)
        puts "  #{BOLD}#{ip}:#{RST}"
        puts "    Org:      #{data['org']}"
        puts "    Location: #{data['city']}, #{data['region']}, #{data['country']}"
        puts "    Timezone: #{data['timezone']}"
        puts "    Hostname: #{data['hostname']}" if data['hostname']
        puts ""

        @findings[:whois][ip] = data
      end
    rescue => e
      warn "IP lookup failed: #{e.message}"
    end
  end

  # ─── Generate HTML report ────────────────────────────────────

  def generate_report
    section("GENERATING REPORT")
    
    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    report_path = "#{REPORT_DIR}/#{@domain}_#{timestamp}.json"
    html_path = "#{REPORT_DIR}/#{@domain}_#{timestamp}.html"

    # JSON report
    File.write(report_path, JSON.pretty_generate({
      target: @domain,
      timestamp: Time.now.iso8601,
      findings: @findings
    }))
    ok "JSON report: #{report_path}"

    # HTML report
    html = build_html_report
    File.write(html_path, html)
    ok "HTML report: #{html_path}"
  end

  # ─── Run all modules ────────────────────────────────────────

  def run_full
    banner
    enumerate_subdomains
    analyze_headers
    fingerprint_tech
    analyze_tls
    ip_intel
    wayback_check
    generate_report
  end

  private

  def safe_get(uri, redirect: true)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https' || uri.port == 443)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 10
    http.read_timeout = 15

    request = Net::HTTP::Get.new(uri)
    request['User-Agent'] = 'VertexOSINT/1.0'
    
    response = http.request(request)
    
    if redirect && response.is_a?(Net::HTTPRedirection) && response['location']
      return safe_get(URI(response['location']), redirect: true)
    end

    response
  rescue => e
    warn "HTTP request failed for #{uri}: #{e.message}"
    nil
  end

  def truncate(str, max)
    str.length > max ? str[0...max] + "..." : str
  end

  def banner
    puts "#{PURPLE}"
    puts "  ╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦   ╔═╗╔═╗╦╔╗╔╔╦╗"
    puts "  ╚╗╔╝║╣ ╠╦╝ ║ ║╣ ╔╩╦╝   ║ ║╚═╗║║║║ ║ "
    puts "   ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═   ╚═╝╚═╝╩╝╚╝ ╩ "
    puts "#{RST}#{CYAN}  Ruby Intelligence Gathering Engine v1.0#{RST}"
    puts "  Target: #{BOLD}#{@domain}#{RST}"
    puts "  #{Time.now}"
    puts "  ─────────────────────────────────────────"
    puts ""
  end

  def section(title)
    puts "\n#{GREEN}══════════════════════════════════════════════════#{RST}"
    puts "#{GREEN}  #{title}#{RST}"
    puts "#{GREEN}══════════════════════════════════════════════════#{RST}\n"
  end

  def info(msg)    = puts("  #{CYAN}[*]#{RST} #{msg}")
  def ok(msg)      = puts("  #{GREEN}[✓]#{RST} #{msg}")
  def warn(msg)    = puts("  #{RED}[!]#{RST} #{msg}")
  def finding(msg) = puts("  #{YELLOW}[→]#{RST} #{msg}")

  def build_html_report
    <<~HTML
    <!DOCTYPE html>
    <html><head>
    <meta charset="utf-8">
    <title>VERTEX OSINT — #{@domain}</title>
    <style>
      body{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:2rem;max-width:900px;margin:auto}
      h1{color:#bb86fc}h2{color:#03dac6;border-bottom:1px solid #333;padding-bottom:.5rem}
      .ok{color:#00e676}.warn{color:#ff5252}.info{color:#82b1ff}
      .finding{color:#ffd740}pre{background:#1a1a1a;padding:1rem;overflow-x:auto;border-radius:4px}
      table{width:100%;border-collapse:collapse}td,th{padding:.5rem;text-align:left;border-bottom:1px solid #222}
      th{color:#03dac6}.tag{background:#1e1e1e;padding:2px 8px;border-radius:3px;margin:2px;display:inline-block}
    </style></head><body>
    <h1>VERTEX OSINT Report</h1>
    <p>Target: <strong>#{@domain}</strong><br>Generated: #{Time.now}</p>
    
    <h2>Subdomains (#{@findings[:subdomains].length})</h2>
    <pre>#{@findings[:subdomains].join("\n")}</pre>
    
    <h2>Technologies</h2>
    #{@findings[:technologies].map { |t| "<span class='tag'>#{t[:type]}: #{t[:name]}</span>" }.join(' ')}
    
    <h2>Security Headers</h2>
    <table><tr><th>Header</th><th>Value</th></tr>
    #{@findings[:headers].map { |k,v| "<tr><td>#{k}</td><td>#{v[0..80]}</td></tr>" }.join}
    </table>
    
    <h2>Certificate</h2>
    <pre>#{JSON.pretty_generate(@findings[:certificates])}</pre>
    
    <h2>IP Intelligence</h2>
    <pre>#{JSON.pretty_generate(@findings[:whois])}</pre>
    
    <h2>Wayback Snapshots</h2>
    <pre>#{@findings[:wayback]&.map { |w| "#{w[:date]} [#{w[:status]}] #{w[:url]}" }&.join("\n")}</pre>
    
    </body></html>
    HTML
  end
end

# ─── CLI ──────────────────────────────────────────────────────

if ARGV.empty?
  puts "#{PURPLE}VERTEX-OSINT#{Colors::RST} — Ruby Intelligence Engine"
  puts ""
  puts "Usage:"
  puts "  vertex-osint full <domain>       Run all OSINT modules"
  puts "  vertex-osint subs <domain>       Subdomain enumeration"
  puts "  vertex-osint headers <domain>    HTTP security headers"  
  puts "  vertex-osint tech <domain>       Technology fingerprint"
  puts "  vertex-osint tls <domain>        TLS/cert analysis"
  puts "  vertex-osint ip <domain>         IP intelligence"
  puts "  vertex-osint wayback <domain>    Wayback Machine history"
  exit 0
end

cmd = ARGV[0]
domain = ARGV[1]

unless domain
  STDERR.puts "Error: domain required"
  exit 1
end

scanner = VertexOSINT.new(domain)

case cmd
when 'full'    then scanner.run_full
when 'subs'    then scanner.enumerate_subdomains
when 'headers' then scanner.analyze_headers
when 'tech'    then scanner.fingerprint_tech
when 'tls'     then scanner.analyze_tls
when 'ip'      then scanner.ip_intel
when 'wayback' then scanner.wayback_check
else
  STDERR.puts "Unknown command: #{cmd}"
end
