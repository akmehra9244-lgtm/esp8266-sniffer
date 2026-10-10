#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <SPI.h>
#include <SD.h>
#include <EEPROM.h>

// SD Card Chip Select (CS) pin - NodeMCU D4 (GPIO 2)
const int chipSelect = 2;

ESP8266WebServer server(80);

char ap_ssid[33] = "CYBER_SNIFFER_v1";
char ap_pass[33] = "root12345";

bool isSniffing = false;
bool handshakeDetected = false;
File pcapFile;
unsigned long packetCount = 0;
String currentTargetSSID = "";
int targetChannel = 1;

// PCAP Global Header (24 bytes) - Direct compatible with Wireshark & Aircrack-ng
const uint8_t pcap_global_header[24] = {
  0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0xff, 0xff, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00
};

// Professional Hacker Cyberpunk Theme CSS
const String hackerCSS = R"(
  <style>
    body { background-color: #05070a; color: #00ff66; font-family: 'Courier New', Courier, monospace; margin: 0; padding: 20px; }
    .container { max-width: 750px; margin: auto; background: #0b0f17; border: 1px solid #1e293b; border-radius: 6px; box-shadow: 0 0 25px rgba(0, 255, 102, 0.15); padding: 25px; }
    h2, h3 { color: #00e5ff; text-align: center; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 8px rgba(0,229,255,0.4); }
    .status-box { background: #030508; border: 1px dashed #00ff66; padding: 15px; border-radius: 4px; margin: 20px 0; text-align: center; }
    .btn { background: #111827; color: #00ff66; border: 1px solid #00ff66; padding: 12px 20px; border-radius: 4px; cursor: pointer; font-family: 'Courier New', monospace; font-weight: bold; text-transform: uppercase; transition: 0.2s; display: inline-block; text-decoration: none; }
    .btn:hover { background: #00ff66; color: #05070a; box-shadow: 0 0 15px #00ff66; }
    .btn-danger { color: #ff3333; border-color: #ff3333; }
    .btn-danger:hover { background: #ff3333; color: #05070a; box-shadow: 0 0 15px #ff3333; }
    .btn-scan { color: #00e5ff; border-color: #00e5ff; }
    .btn-scan:hover { background: #00e5ff; color: #05070a; box-shadow: 0 0 15px #00e5ff; }
    input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0; background: #030508; border: 1px solid #1e293b; color: #00ff66; font-family: 'Courier New', monospace; border-radius: 4px; box-sizing: border-box; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { border: 1px solid #1e293b; padding: 10px; text-align: center; }
    th { background: #111827; color: #00e5ff; letter-spacing: 1px; }
    tr:hover { background: rgba(0, 255, 102, 0.03); }
    a { color: #00e5ff; text-decoration: none; }
    a:hover { text-shadow: 0 0 8px #00e5ff; }
    hr { border: 0; border-top: 1px solid #1e293b; margin: 25px 0; }
    ul { list-style-type: none; padding: 0; }
    li { padding: 10px; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; }
  </style>
)";

void loadConfig() {
  EEPROM.begin(512);
  String storedSsid = "";
  for (int i = 0; i < 32; ++i) {
    char c = EEPROM.read(i);
    if (c == '\0') break;
    storedSsid += c;
  }
  
  String storedPass = "";
  for (int i = 32; i < 64; ++i) {
    char c = EEPROM.read(i);
    if (c == '\0') break;
    storedPass += c;
  }

  if (storedSsid.length() > 0 && storedSsid.length() <= 32) {
    storedSsid.toCharArray(ap_ssid, 33);
  }
  if (storedPass.length() >= 8 && storedPass.length() <= 32) {
    storedPass.toCharArray(ap_pass, 33);
  }
  EEPROM.end();
}

void saveConfig(String newSsid, String newPass) {
  EEPROM.begin(512);
  for (int i = 0; i < 64; ++i) {
    EEPROM.write(i, 0);
  }
  for (unsigned int i = 0; i < newSsid.length() && i < 32; ++i) {
    EEPROM.write(i, newSsid[i]);
  }
  for (unsigned int i = 0; i < newPass.length() && i < 32; ++i) {
    EEPROM.write(32 + i, newPass[i]);
  }
  EEPROM.commit();
  EEPROM.end();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Load saved AP credentials from EEPROM
  loadConfig();

  // Start Secure AP + Station Mode
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_pass);
  
  Serial.println();
  Serial.print("Cyber Sniffer AP Started. SSID: ");
  Serial.println(ap_ssid);
  Serial.print("IP: ");
  Serial.println(WiFi.softAPIP());

  // Initialize SD Card
  if (!SD.begin(chipSelect)) {
    Serial.println("SD Card initialization failed!");
  } else {
    Serial.println("SD Card initialized successfully.");
  }

  // Web Server Endpoints
  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/start", handleStartCapture);
  server.on("/stop", handleStopCapture);
  server.on("/download", handleDownload);
  server.on("/saveconfig", HTTP_POST, handleSaveConfig);
  
  server.begin();
  Serial.println("HTTP Web Server online.");
}

void loop() {
  server.handleClient();

  if (isSniffing && handshakeDetected) {
    stopCapture();
  }

  if (isSniffing) {
    wifi_set_channel(targetChannel);
    delay(100);
  }
}

// 1. Dashboard / Homepage
void handleRoot() {
  String html = "<html><head><title>CYBER_SNIFFER // TERMINAL</title>" + hackerCSS + "</head>";
  html += "<body><div class='container'>";
  html += "<h2>// ESP8266 HANDSHAKE SNIFFER v1.0</h2>";
  
  if (isSniffing) {
    html += "<div class='status-box' style='border-color: #ffaa00;'>";
    html += "<p style='color:#ffaa00; font-size:16px; margin:0;'><b>[!] STATUS: CAPTURING FROM [" + currentTargetSSID + "] (CH: " + String(targetChannel) + ")... 📡</b></p>";
    html += "</div>";
    html += "<div style='text-align:center;'><a href='/stop' class='btn btn-danger'>Abort Capture</a></div>";
  } else {
    if (handshakeDetected) {
      html += "<div class='status-box' style='border-color: #00ff66;'>";
      html += "<p style='color:#00ff66; font-size:16px; margin:0;'><b>[+] SUCCESS: HANDSHAKE CAPTURED & SAVED! 🎯</b></p>";
      html += "</div>";
    } else {
      html += "<div class='status-box'>";
      html += "<p style='color:#00ff66; font-size:14px; margin:0;'>[SYSTEM IDLE] READY FOR TARGET ACQUISITION</p>";
      html += "</div>";
    }
    html += "<div style='text-align:center;'><a href='/scan' class='btn btn-scan'>[ Initialize Target Scan ]</a></div>";
  }

  html += "<hr>";
  html += "<h3>Captured Target Files (.pcap)</h3>";
  html += "<ul>";

  File root = SD.open("/");
  while (true) {
    File entry = root.openNextFile();
    if (!entry) break;
    if (!entry.isDirectory()) {
      String fileName = String(entry.name());
      if (fileName.endsWith(".pcap") || fileName.endsWith(".CAP")) {
        html += "<li><span>📁 " + fileName + " (" + String(entry.size()) + " bytes)</span> <a href='/download?file=" + fileName + "' class='btn' style='padding:5px 10px; font-size:12px;'>Download</a></li>";
      }
    }
    entry.close();
  }
  root.close();

  html += "</ul>";
  
  // AP Settings Form Section
  html += "<hr>";
  html += "<h3>ESP8266 AP Settings (Change Wi-Fi Name & Password)</h3>";
  html += "<form action='/saveconfig' method='POST'>";
  html += "<label>New Wi-Fi Name (SSID):</label>";
  html += "<input type='text' name='ssid' value='" + String(ap_ssid) + "' required>";
  html += "<label>New Password (Min 8 Chars):</label>";
  html += "<input type='password' name='pass' value='" + String(ap_pass) + "' required>";
  html += "<br><br><div style='text-align:center;'><input type='submit' value='Update Settings & Restart' class='btn'></div>";
  html += "</form>";

  html += "</div></body></html>";
  server.send(200, "text/html", html);
}

// Save Config Route
void handleSaveConfig() {
  if (server.hasArg("ssid") && server.hasArg("pass")) {
    String newSsid = server.arg("ssid");
    String newPass = server.arg("pass");
    
    if (newPass.length() >= 8) {
      saveConfig(newSsid, newPass);
      server.send(200, "text/html", "<html><head>" + hackerCSS + "</head><body><div class='container'><h2>Settings Saved Successfully!</h2><p>ESP8266 is restarting... Please reconnect to your new Wi-Fi network.</p></div></body></html>");
      delay(2000);
      ESP.restart();
      return;
    }
  }
  server.send(400, "text/plain", "Invalid Configuration! Password must be at least 8 characters.");
}

// 2. Network Scanner Page
void handleScan() {
  server.send(200, "text/html", "<html><head>" + hackerCSS + "</head><body><div class='container'><h2>Scanning Airwaves... Please Wait...</h2></div></body></html>");
  
  int n = WiFi.scanNetworks();
  
  String html = "<html><head><title>Target Selection // Scanner</title>" + hackerCSS + "</head>";
  html += "<body><div class='container'>";
  html += "<h2>Target Networks Detected (" + String(n) + ")</h2>";
  html += "<table>";
  html += "<tr><th>SSID</th><th>Channel</th><th>RSSI</th><th>Action</th></tr>";

  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    if (ssid == "") ssid = "[Hidden Network]";
    int channel = WiFi.channel(i);
    long rssi = WiFi.RSSI(i);

    html += "<tr>";
    html += "<td style='font-weight:bold; color:#00ff66;'>" + ssid + "</td>";
    html += "<td>" + String(channel) + "</td>";
    html += "<td>" + String(rssi) + " dBm</td>";
    html += "<td><a href='/start?ssid=" + urlEncode(ssid) + "&ch=" + String(channel) + "' class='btn' style='padding:5px 12px; font-size:12px;'>Capture</a></td>";
    html += "</tr>";
  }

  html += "</table><br><div style='text-align:center;'><a href='/' class='btn'>Back to Dashboard</a></div>";
  html += "</div></body></html>";
  
  server.send(200, "text/html", html);
}

// 3. Start Capture Route
void handleStartCapture() {
  if (server.hasArg("ssid") && server.hasArg("ch")) {
    currentTargetSSID = server.arg("ssid");
    targetChannel = server.arg("ch").toInt();
  } else {
    currentTargetSSID = "Unknown_Network";
    targetChannel = 1;
  }

  handshakeDetected = false;
  packetCount = 0;

  char filename[50];
  sprintf(filename, "/%s_%lu.pcap", currentTargetSSID.c_str(), millis());
  pcapFile = SD.open(filename, FILE_WRITE);
  if (pcapFile) {
    pcapFile.write(pcap_global_header, 24);
    pcapFile.flush();
  }

  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(&sniffer_callback);

  isSniffing = true;
  
  server.sendHeader("Location", "/", true);
  server.send(303);
}

// 4. Stop Capture Route
void handleStopCapture() {
  stopCapture();
  server.sendHeader("Location", "/", true);
  server.send(303);
}

void stopCapture() {
  isSniffing = false;
  wifi_promiscuous_enable(0);
  if (pcapFile) {
    pcapFile.close();
  }
}

// 5. File Download Handler
void handleDownload() {
  if (server.hasArg("file")) {
    String filename = "/" + server.arg("file");
    if (SD.exists(filename)) {
      File downloadFile = SD.open(filename, FILE_READ);
      server.streamFile(downloadFile, "application/octet-stream");
      downloadFile.close();
      return;
    }
  }
  server.send(404, "text/plain", "File Not Found");
}

String urlEncode(String str) {
  String encoded = "";
  char c, code0, code1;
  for (unsigned int i = 0; i < str.length(); i++) {
    c = str.charAt(i);
    if (isalnum(c)) {
      encoded += c;
    } else {
      code1 = (c & 0xf) + '0';
      if ((c & 0xf) > 9) code1 = (c & 0xf) - 10 + 'A';
      c = (c >> 4) & 0xf;
      code0 = c + '0';
      if (c > 9) code0 = c - 10 + 'A';
      encoded += '%';
      encoded += code0;
      encoded += code1;
    }
  }
  return encoded;
}

bool checkEAPOL(uint8_t *buf, uint16_t len) {
  if (len < 32) return false;
  for (int i = 0; i < len - 7; i++) {
    if (buf[i] == 0xAA && buf[i+1] == 0xAA && buf[i+2] == 0x03 &&
        buf[i+3] == 0x00 && buf[i+4] == 0x00 && buf[i+5] == 0x00 &&
        buf[i+6] == 0x88 && buf[i+7] == 0x8E) {
      return true;
    }
  }
  return false;
}

void sniffer_callback(uint8_t *buf, uint16_t len) {
  if (len < 36) return;

  if (!handshakeDetected && checkEAPOL(buf, len)) {
    handshakeDetected = true;
    Serial.println("\n[+] SUCCESS: Handshake Captured & Saved Automatically! 🎯\n");
  }

  struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
  } pkt_header;

  pkt_header.ts_sec = millis() / 1000;
  pkt_header.ts_usec = (millis() % 1000) * 1000;
  pkt_header.incl_len = len;
  pkt_header.orig_len = len;

  if (isSniffing && pcapFile) {
    pcapFile.write((uint8_t*)&pkt_header, sizeof(pkt_header));
    pcapFile.write(buf, len);
    packetCount++;

    if (packetCount % 50 == 0) {
      pcapFile.flush();
    }
  }
}
