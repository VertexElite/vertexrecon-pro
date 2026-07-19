/* ═══════════════════════════════════════════════════════════════
   VERTEX-PATTERN — C Binary Pattern Matcher
   Signature scanning, hex pattern matching, entropy sectioning,
   structure anomaly detection, format identification.

   Native, dependency-free (libc + libm only) — builds with clang/gcc
   on Termux/Android and Linux. Port of the original OCaml implementation.
   ═══════════════════════════════════════════════════════════════ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define RED    "\033[0;31m"
#define GREEN  "\033[0;32m"
#define YELLOW "\033[1;33m"
#define CYAN   "\033[0;36m"
#define PURPLE "\033[0;35m"
#define BOLD   "\033[1m"
#define RST    "\033[0m"

/* ─── File magic signatures ─────────────────────────────────── */

typedef struct {
    const char   *name;
    const unsigned char magic[8];
    int           maglen;
    int           offset;
    const char   *risk; /* none, low, medium, high */
} file_sig;

static const file_sig signatures[] = {
    { "ELF Binary",      {0x7F,0x45,0x4C,0x46},      4, 0, "medium" },
    { "PE/Windows EXE",  {0x4D,0x5A},                2, 0, "high"   },
    { "Mach-O (64-bit)", {0xCF,0xFA,0xED,0xFE},      4, 0, "medium" },
    { "Mach-O (32-bit)", {0xCE,0xFA,0xED,0xFE},      4, 0, "medium" },
    { "Java Class",      {0xCA,0xFE,0xBA,0xBE},      4, 0, "medium" },
    { "DEX (Android)",   {0x64,0x65,0x78,0x0A},      4, 0, "medium" },
    { "ZIP/APK/JAR",     {0x50,0x4B,0x03,0x04},      4, 0, "low"    },
    { "RAR Archive",     {0x52,0x61,0x72,0x21},      4, 0, "low"    },
    { "GZIP",            {0x1F,0x8B},                2, 0, "none"   },
    { "7z Archive",      {0x37,0x7A,0xBC,0xAF},      4, 0, "low"    },
    { "PDF",             {0x25,0x50,0x44,0x46},      4, 0, "low"    },
    { "PNG Image",       {0x89,0x50,0x4E,0x47},      4, 0, "none"   },
    { "JPEG Image",      {0xFF,0xD8,0xFF},           3, 0, "none"   },
    { "GIF Image",       {0x47,0x49,0x46,0x38},      4, 0, "none"   },
    { "SQLite DB",       {0x53,0x51,0x4C,0x69},      4, 0, "low"    },
    { "Shell Script",    {0x23,0x21,0x2F},           3, 0, "low"    },
};
static const int NUM_SIGS = (int)(sizeof(signatures)/sizeof(signatures[0]));

/* Malware-specific byte patterns */
typedef struct {
    const char   *threat_name;
    const unsigned char pattern[16];
    int           patlen;
    const char   *description;
} threat_sig;

static const threat_sig threat_patterns[] = {
    { "Metasploit Shellcode (x86)",
      {0x31,0xC0,0x50,0x68,0x2F,0x2F,0x73,0x68}, 8,
      "xor eax,eax; push eax; push '//sh'" },
    { "Metasploit Shellcode (x64)",
      {0x48,0x31,0xF6,0x56,0x48,0xBF,0x2F,0x62}, 8,
      "xor rsi,rsi; push rsi; movabs rdi,'/b'" },
    { "Cobalt Strike Beacon",
      {0xFC,0x48,0x83,0xE4,0xF0,0xE8}, 6,
      "Classic CS stager prologue" },
    { "PHP Webshell",
      {0x3C,0x3F,0x70,0x68,0x70,0x20,0x65,0x76,0x61,0x6C}, 10,
      "<?php eval" },
    { "Base64 Exec Pattern",
      {0x62,0x61,0x73,0x65,0x36,0x34,0x20,0x2D,0x64}, 9,
      "base64 -d" },
    { "Reverse Shell Pattern",
      {0x2F,0x64,0x65,0x76,0x2F,0x74,0x63,0x70,0x2F}, 9,
      "/dev/tcp/" },
    { "LD_PRELOAD Hijack",
      {0x4C,0x44,0x5F,0x50,0x52,0x45,0x4C,0x4F,0x41,0x44}, 10,
      "LD_PRELOAD" },
    { "Ptrace Anti-Debug",
      {0x70,0x74,0x72,0x61,0x63,0x65}, 6,
      "ptrace call (anti-debugging)" },
};
static const int NUM_THREATS = (int)(sizeof(threat_patterns)/sizeof(threat_patterns[0]));

static const char *suspicious_keywords[] = {
    "password","passwd","shadow","token","secret","api_key",
    "/bin/sh","/bin/bash","eval(","exec(","system(",
    "base64","wget","curl","reverse","shell","payload",
    "c2","beacon","callback","exfil","dropper",
    "ld_preload","ptrace","mprotect","/dev/tcp",
};
static const int NUM_KEYWORDS = (int)(sizeof(suspicious_keywords)/sizeof(suspicious_keywords[0]));

/* ─── Byte utilities ──────────────────────────────────────── */

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

static int matches_at(const unsigned char *data, size_t len, size_t off,
                      const unsigned char *pat, int plen) {
    if (off + (size_t)plen > len) return 0;
    for (int i = 0; i < plen; i++)
        if (data[off + i] != pat[i]) return 0;
    return 1;
}

/* case-insensitive substring search (avoids GNU strcasestr dependency) */
static int ci_contains(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0) return 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl) return 1;
    }
    return 0;
}

/* ─── Shannon entropy ─────────────────────────────────────── */

static double shannon_entropy(const unsigned char *data, size_t len) {
    if (len == 0) return 0.0;
    unsigned long freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double flen = (double)len, e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            double p = (double)freq[i] / flen;
            e -= p * (log(p) / log(2.0));
        }
    }
    return e;
}

static const char *entropy_color(double e) {
    if (e > 7.5) return RED;
    if (e > 6.5) return YELLOW;
    if (e > 4.0) return GREEN;
    return CYAN;
}

static const char *entropy_label(double e) {
    if (e > 7.5) return "PACKED/ENCRYPTED";
    if (e > 6.5) return "HIGH (compressed/encoded)";
    if (e > 4.0) return "NORMAL";
    return "LOW (mostly text)";
}

/* ─── Display helpers ─────────────────────────────────────── */

static void section(const char *title) {
    printf("\n%s══════════════════════════════════════════════════%s\n", GREEN, RST);
    printf("%s  %s%s\n", GREEN, title, RST);
    printf("%s══════════════════════════════════════════════════%s\n", GREEN, RST);
}

static void print_hex_dump(const unsigned char *data, size_t len,
                           size_t offset, size_t length) {
    size_t actual = length;
    if (offset + actual > len) actual = (offset < len) ? len - offset : 0;
    size_t i = 0;
    while (i < actual) {
        printf("    %08lX  ", (unsigned long)(offset + i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < actual) printf("%02X ", data[offset + i + j]);
            else                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < actual) {
                unsigned char b = data[offset + i + j];
                putchar((b >= 0x20 && b < 0x7F) ? (int)b : '.');
            }
        }
        printf("|\n");
        i += 16;
    }
}

/* ─── Core analyses ───────────────────────────────────────── */

static int identify_and_print(const unsigned char *data, size_t len) {
    int found = 0;
    for (int s = 0; s < NUM_SIGS; s++) {
        if (matches_at(data, len, (size_t)signatures[s].offset,
                       signatures[s].magic, signatures[s].maglen)) {
            const char *rc = GREEN;
            if      (strcmp(signatures[s].risk, "high")   == 0) rc = RED;
            else if (strcmp(signatures[s].risk, "medium") == 0) rc = YELLOW;
            else if (strcmp(signatures[s].risk, "low")    == 0) rc = CYAN;
            printf("  %s[→]%s %s (risk: %s%s%s)\n",
                   YELLOW, RST, signatures[s].name, rc, signatures[s].risk, RST);
            found++;
        }
    }
    return found;
}

static void scan_threats(const unsigned char *data, size_t len) {
    int total = 0;
    for (int t = 0; t < NUM_THREATS; t++) {
        int plen = threat_patterns[t].patlen;
        int hits = 0;
        for (size_t i = 0; i + (size_t)plen <= len; i++) {
            if (matches_at(data, len, i, threat_patterns[t].pattern, plen)) {
                if (hits == 0) {
                    printf("\n  %s%s%s — %s\n", RED,
                           threat_patterns[t].threat_name, RST,
                           threat_patterns[t].description);
                }
                printf("    Found at offset 0x%06lX:\n", (unsigned long)i);
                print_hex_dump(data, len, i, 32);
                hits++;
                total++;
            }
        }
    }
    if (total == 0)
        printf("  %s[✓] No known threat signatures detected%s\n", GREEN, RST);
}

static void interesting_strings(const unsigned char *data, size_t len) {
    /* collect printable runs >= 8 chars, flag suspicious */
    size_t start = 0, run = 0;
    long total = 0, suspicious = 0;
    /* first pass: counts */
    for (size_t i = 0; i <= len; i++) {
        int printable = (i < len) && (data[i] >= 0x20 && data[i] < 0x7F);
        if (printable) { if (run == 0) start = i; run++; }
        else {
            if (run >= 8) {
                total++;
                char *s = (char *)malloc(run + 1);
                memcpy(s, data + start, run); s[run] = 0;
                for (int k = 0; k < NUM_KEYWORDS; k++)
                    if (ci_contains(s, suspicious_keywords[k])) { suspicious++; break; }
                free(s);
            }
            run = 0;
        }
    }

    printf("  Total strings (>=8 chars): %ld\n", total);
    printf("  Suspicious matches: %s%ld%s\n",
           suspicious ? RED : GREEN, suspicious, RST);

    if (suspicious > 0) {
        printf("\n  %sFlagged strings:%s\n", BOLD, RST);
        run = 0; start = 0;
        for (size_t i = 0; i <= len; i++) {
            int printable = (i < len) && (data[i] >= 0x20 && data[i] < 0x7F);
            if (printable) { if (run == 0) start = i; run++; }
            else {
                if (run >= 8) {
                    char *s = (char *)malloc(run + 1);
                    memcpy(s, data + start, run); s[run] = 0;
                    int flag = 0;
                    for (int k = 0; k < NUM_KEYWORDS; k++)
                        if (ci_contains(s, suspicious_keywords[k])) { flag = 1; break; }
                    if (flag) {
                        if (run > 80) s[80] = 0;
                        printf("  %s[0x%06lX]%s %s%s\n", YELLOW,
                               (unsigned long)start, RST, s, run > 80 ? "..." : "");
                    }
                    free(s);
                }
                run = 0;
            }
        }
    }
}

static void analyze_file(const char *path) {
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "  %s[!]%s Cannot read: %s\n", RED, RST, path); return; }

    printf("\n%sVERTEX-PATTERN%s — Binary Analysis\n", PURPLE, RST);
    printf("  File: %s%s%s\n", BOLD, path, RST);
    printf("  Size: %lu bytes\n", (unsigned long)len);

    section("FILE IDENTIFICATION");
    if (identify_and_print(data, len) == 0)
        printf("  %s[?]%s Unknown file format\n", YELLOW, RST);

    section("ENTROPY ANALYSIS");
    double ent = shannon_entropy(data, len);
    const char *ec = entropy_color(ent);
    printf("  Overall: %s%.4f%s bits/byte — %s%s%s\n",
           ec, ent, RST, ec, entropy_label(ent), RST);

    size_t block = 4096;
    size_t nblocks = (len + block - 1) / block;
    if (nblocks == 0) nblocks = 1;
    printf("  Blocks: %lu x %lu bytes\n\n", (unsigned long)nblocks, (unsigned long)block);

    printf("  %sEntropy Map:%s\n", BOLD, RST);
    for (size_t off = 0; off < len; off += block) {
        size_t bl = (off + block <= len) ? block : (len - off);
        double e = shannon_entropy(data + off, bl);
        int bar_len = (int)(e * 6.0);
        char bar[64];
        if (bar_len > 42) bar_len = 42;
        if (bar_len < 0) bar_len = 0;
        for (int k = 0; k < bar_len; k++) bar[k] = '#';
        bar[bar_len] = 0;
        printf("    0x%06lX |%s%-42s%s| %.3f\n",
               (unsigned long)off, entropy_color(e), bar, RST, e);
    }

    /* high-entropy sections */
    int high_hdr = 0;
    for (size_t off = 0; off < len; off += block) {
        size_t bl = (off + block <= len) ? block : (len - off);
        double e = shannon_entropy(data + off, bl);
        if (e > 7.5) {
            if (!high_hdr) {
                printf("\n  %s[!] High-entropy sections (possible encryption/packing):%s\n", RED, RST);
                high_hdr = 1;
            }
            printf("    Offset 0x%06lX: %.4f\n", (unsigned long)off, e);
            print_hex_dump(data, len, off, 64);
        }
    }

    section("THREAT SIGNATURE SCAN");
    scan_threats(data, len);

    section("INTERESTING STRINGS");
    interesting_strings(data, len);

    printf("\n");
    free(data);
}

static void entropy_only(const char *path) {
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "  %s[!]%s Cannot read: %s\n", RED, RST, path); return; }
    section("ENTROPY ANALYSIS");
    size_t block = 4096;
    for (size_t off = 0; off < len; off += block) {
        size_t bl = (off + block <= len) ? block : (len - off);
        double e = shannon_entropy(data + off, bl);
        printf("  0x%06lX: %s%.4f%s %s\n",
               (unsigned long)off, entropy_color(e), e, RST, entropy_label(e));
    }
    free(data);
}

static void threats_only(const char *path) {
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "  %s[!]%s Cannot read: %s\n", RED, RST, path); return; }
    section("THREAT SCAN");
    scan_threats(data, len);
    free(data);
}

static void identify_only(const char *path) {
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "  %s[!]%s Cannot read: %s\n", RED, RST, path); return; }
    for (int s = 0; s < NUM_SIGS; s++)
        if (matches_at(data, len, (size_t)signatures[s].offset,
                       signatures[s].magic, signatures[s].maglen))
            printf("  %s (risk: %s)\n", signatures[s].name, signatures[s].risk);
    free(data);
}

static void hex_search(const char *path, const char *hex) {
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "  %s[!]%s Cannot read: %s\n", RED, RST, path); return; }

    int hlen = (int)strlen(hex);
    if (hlen <= 0 || hlen % 2 != 0) {
        fprintf(stderr, "  %s[!]%s Hex pattern must have an even number of hex digits\n", RED, RST);
        free(data); return;
    }
    int plen = hlen / 2;
    unsigned char *pat = (unsigned char *)malloc((size_t)plen);
    for (int i = 0; i < plen; i++) {
        char byte[3] = { hex[i*2], hex[i*2+1], 0 };
        char *end = NULL;
        long v = strtol(byte, &end, 16);
        if (end == byte || *end != 0) {
            fprintf(stderr, "  %s[!]%s Invalid hex: %s\n", RED, RST, hex);
            free(pat); free(data); return;
        }
        pat[i] = (unsigned char)v;
    }

    char title[128];
    snprintf(title, sizeof(title), "HEX PATTERN SEARCH: %s", hex);
    section(title);

    int hits = 0;
    for (size_t i = 0; i + (size_t)plen <= len; i++) {
        if (matches_at(data, len, i, pat, plen)) {
            if (hits == 0) printf("  %s[!] Found occurrence(s):%s\n", YELLOW, RST);
            printf("    Offset 0x%06lX:\n", (unsigned long)i);
            print_hex_dump(data, len, i, 48);
            hits++;
        }
    }
    if (hits == 0) printf("  %s[✓] Pattern not found%s\n", GREEN, RST);

    free(pat);
    free(data);
}

/* ─── CLI ─────────────────────────────────────────────────── */

static void usage(void) {
    printf("\n%sVERTEX-PATTERN%s — C Binary Pattern Matcher\n\n", PURPLE, RST);
    printf("Usage:\n");
    printf("  vertex-pattern analyze <file>           Full binary analysis\n");
    printf("  vertex-pattern entropy <file>           Entropy analysis only\n");
    printf("  vertex-pattern threats <file>           Threat signature scan\n");
    printf("  vertex-pattern hex <file> <hex_pattern> Search hex pattern\n");
    printf("  vertex-pattern identify <file>          File type identification\n\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 0; }

    const char *cmd = argv[1];
    if      (strcmp(cmd, "analyze")  == 0 && argc >= 3) analyze_file(argv[2]);
    else if (strcmp(cmd, "entropy")  == 0 && argc >= 3) entropy_only(argv[2]);
    else if (strcmp(cmd, "threats")  == 0 && argc >= 3) threats_only(argv[2]);
    else if (strcmp(cmd, "hex")      == 0 && argc >= 4) hex_search(argv[2], argv[3]);
    else if (strcmp(cmd, "identify") == 0 && argc >= 3) identify_only(argv[2]);
    else {
        fprintf(stderr, "Unknown command or missing args: %s\n", cmd);
        usage();
        return 1;
    }
    return 0;
}
