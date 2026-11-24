/*
  cc1101-nmap companion firmware for the Evil Crow RF V2 (ESP32 + 2x CC1101)

  RECEIVE ONLY. This firmware never puts either CC1101 into TX.

  Module 1 ("hunter") continuously sweeps a list of frequencies and keeps a
  peak-hold / average RSSI per frequency. That is what lets the scanner see
  transmitters a CC1101 cannot demodulate (P25 and TETRA radios, LTE phones,
  LoRa) and judge how close they are.

  Module 2 ("analyst") listens on one frequency at a time, either capturing
  demodulated edge timings (OOK / raw FSK, like the stock firmware but with
  RSSI and glitch filtering), or using the CC1101 packet engine with a sync
  word (FSK weather sensors, wireless M-Bus meters).

  The Python scanner (python3 -m cc1101nmap) drives it over HTTP:
    GET  /                 status page with a link to the scanner dashboard
    GET  /nmap/info        firmware/module info (?dash=PORT tells us the dashboard port)
    POST /nmap/plan        segments=startkHz:stopkHz:stepkHz:rxbwkHz,...  [dwell_us, reads]
    GET  /nmap/spectrum    peak/avg RSSI per planned frequency since the last call
    POST /nmap/rx          module=2 freq_khz mode=ook|fsk_raw|fsk_pkt|ook_pkt rxbw_khz drate dev_khz [sync pktlen manchester min_us end_us squelch]
    GET  /nmap/events      captures and packets newer than ?since=SEQ

  Wi-Fi: same as the stock firmware - SSID and password on the first two
  lines of /wifi_config.txt on the SD card, else the stock default network
  ("Evil Crow RF v2"), else its own access point "cc1101-nmap" at 192.168.4.1.
  mDNS name: evilcrow-rf.local (same as stock, so the scanner finds it).

  Library: SmartRC-CC1101-Driver-Lib (ELECHOUSE_CC1101_SRC_DRV).
*/
#include <Arduino.h>
#include <ESPmDNS.h>
#include <SD.h>
#include <SPI.h>
#include <WebServer.h>
#include <WiFi.h>

#include <ELECHOUSE_CC1101_SRC_DRV.h>

#define FW_VERSION "0.2.0"

static const char *HOSTNAME = "evilcrow-rf";
static const char *STOCK_SSID = "Evil Crow RF v2";      // stock firmware's default client network
static const char *STOCK_PASS = "123456789ECRFv2";
static const char *AP_SSID = "cc1101-nmap";
static const char *AP_PASS = "cc1101nmap";

// ---- Evil Crow RF V2 wiring ------------------------------------------------
static const int PIN_SCK = 14, PIN_MISO = 12, PIN_MOSI = 13;
static const int PIN_CS[2] = {5, 27};
static const int PIN_GDO0[2] = {2, 25};
static const int PIN_GDO2[2] = {4, 26};   // async serial data out
static const int SD_SCK = 18, SD_MISO = 19, SD_MOSI = 23, SD_CS = 22;
static const int HUNTER = 0, ANALYST = 1;

WebServer server(80);
static bool moduleOk[2] = {false, false};
static IPAddress dashIp;
static uint16_t dashPort = 0;
static uint32_t eventSeq = 0;
static uint32_t droppedEvents = 0;

// ---- hunter: RSSI sweep ------------------------------------------------------
#define MAX_POINTS 1024
static uint32_t planHz[MAX_POINTS];
static uint16_t planBw[MAX_POINTS];
static int8_t peakDbm[MAX_POINTS], lastPeak[MAX_POINTS], lastAvg[MAX_POINTS];
static int32_t sumDbm[MAX_POINTS];
static uint16_t cntDbm[MAX_POINTS];
static int nPoints = 0, cursorPt = 0;
static uint32_t sweepsDone = 0, sweepStartMs = 0, lastSweepMs = 0;
static uint16_t dwellUs = 350;
static uint8_t readsPerPoint = 3;
static uint16_t currentBw = 0;

// ---- analyst: capture / packets ----------------------------------------------
enum Mode : uint8_t { M_OFF = 0, M_OOK = 1, M_FSK_RAW = 2, M_FSK_PKT = 3, M_OOK_PKT = 4 };
static const char *MODE_NAMES[] = {"off", "ook", "fsk_raw", "fsk_pkt", "ook_pkt"};

struct AnalystCfg {
  Mode mode = M_OFF;
  uint32_t freqKhzX10 = 4339200;
  float rxbw = 270, drate = 5, dev = 0;
  uint8_t sync1 = 0x2D, sync0 = 0xD4, pktlen = 20;
  bool manchester = false;
  uint16_t minUs = 60;
  uint32_t endUs = 15000;
  int8_t squelch = -95;
} acfg;

#define CAP_MAX 1536
#define MIN_EDGES 24
static uint16_t capA[CAP_MAX], capB[CAP_MAX];
static volatile uint16_t *capActive = capA;
static volatile uint16_t *capPending = nullptr;
static volatile uint16_t capLen = 0, pendingLen = 0;
static volatile uint32_t lastEdgeUs = 0, mergeCarry = 0;
static volatile bool merging = false;
static portMUX_TYPE capMux = portMUX_INITIALIZER_UNLOCKED;
static int8_t capMaxRssi = -128;

struct CapEvent {
  uint32_t seq, ms, freqKhzX10;
  uint8_t mode;
  int8_t rssi;
  uint16_t len;
  uint16_t data[CAP_MAX];
};
#define CAP_SLOTS 6
static CapEvent capEvents[CAP_SLOTS];
static int capHead = 0;

struct PktEvent {
  uint32_t seq, ms, freqKhzX10;
  uint8_t sync1, sync0, len, lqi;
  int8_t rssi;
  uint8_t data[62];
};
#define PKT_SLOTS 16
static PktEvent pktEvents[PKT_SLOTS];
static int pktHead = 0;

// ---------------------------------------------------------------------------
static int8_t rawToDbm(uint8_t raw) {
  int v = raw >= 128 ? ((int)raw - 256) / 2 - 74 : raw / 2 - 74;
  return (int8_t)constrain(v, -128, 0);
}

static void IRAM_ATTR pushEdge(uint32_t d) {
  if (capLen >= CAP_MAX) return;
  capActive[capLen++] = d > 65535 ? 65535 : (uint16_t)d;
}

// Swap the active buffer into the pending slot (caller holds capMux).
static void IRAM_ATTR finishCapture() {
  if (capLen >= MIN_EDGES && pendingLen == 0) {
    capPending = capActive;
    pendingLen = capLen;
    capActive = (capActive == capA) ? capB : capA;
  } else if (capLen >= MIN_EDGES) {
    droppedEvents++;
  }
  capLen = 0;
  merging = false;
}

// One interrupt per edge of the demodulated signal. Pulses shorter than
// minUs are glitches: they are merged into the surrounding level so mark/space
// alternation is preserved (the stock firmware drops them, which flips it).
static void IRAM_ATTR edgeIsr() {
  uint32_t now = micros();
  uint32_t d = now - lastEdgeUs;
  lastEdgeUs = now;
  portENTER_CRITICAL_ISR(&capMux);
  if (d > acfg.endUs) {               // silence ended: this edge starts a new burst
    if (capLen) finishCapture();
  } else if (merging) {
    pushEdge(mergeCarry + d);
    merging = false;
  } else if (d < acfg.minUs) {
    if (capLen) {
      mergeCarry = capActive[--capLen] + d;
      merging = true;
    }
  } else {
    pushEdge(d);
    if (capLen >= CAP_MAX) finishCapture();
  }
  portEXIT_CRITICAL_ISR(&capMux);
}

// ---------------------------------------------------------------------------
static void hunterStep(int maxPoints) {
  if (!moduleOk[HUNTER] || nPoints == 0) return;
  ELECHOUSE_cc1101.setModul(HUNTER);
  for (int k = 0; k < maxPoints; k++) {
    int i = cursorPt;
    if (planBw[i] != currentBw) {
      ELECHOUSE_cc1101.setRxBW(planBw[i]);
      currentBw = planBw[i];
    }
    ELECHOUSE_cc1101.setSidle();
    ELECHOUSE_cc1101.setMHZ(planHz[i] / 1e6f);
    ELECHOUSE_cc1101.SetRx();          // IDLE->RX runs the synthesizer auto-calibration
    delayMicroseconds(dwellUs);
    int pk = -128, sum = 0;
    for (int r = 0; r < readsPerPoint; r++) {
      int v = ELECHOUSE_cc1101.getRssi();
      pk = max(pk, v);
      sum += v;
      if (r + 1 < readsPerPoint) delayMicroseconds(80);
    }
    pk = constrain(pk, -128, 0);
    peakDbm[i] = cntDbm[i] ? max((int)peakDbm[i], pk) : pk;
    sumDbm[i] += sum / readsPerPoint;
    cntDbm[i]++;
    if (++cursorPt >= nPoints) {
      cursorPt = 0;
      sweepsDone++;
      lastSweepMs = millis() - sweepStartMs;
      sweepStartMs = millis();
    }
  }
}

static void storeCapture(volatile uint16_t *buf, uint16_t len, int8_t rssi) {
  CapEvent &e = capEvents[capHead];
  capHead = (capHead + 1) % CAP_SLOTS;
  e.seq = ++eventSeq;
  e.ms = millis();
  e.freqKhzX10 = acfg.freqKhzX10;
  e.mode = acfg.mode;
  e.rssi = rssi;
  e.len = len;
  for (uint16_t i = 0; i < len; i++) e.data[i] = buf[i];
}

static void analystService() {
  if (!moduleOk[ANALYST] || acfg.mode == M_OFF) return;
  ELECHOUSE_cc1101.setModul(ANALYST);
  if (acfg.mode == M_FSK_PKT || acfg.mode == M_OOK_PKT) {
    uint8_t rxb = ELECHOUSE_cc1101.SpiReadStatus(CC1101_RXBYTES);
    uint8_t need = acfg.pktlen + 2;     // + appended RSSI and LQI
    if (rxb & 0x80) {                    // FIFO overflow
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SIDLE);
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SFRX);
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SRX);
    } else if ((rxb & 0x7F) >= need) {
      uint8_t buf[64];
      ELECHOUSE_cc1101.SpiReadBurstReg(CC1101_RXFIFO, buf, need);
      PktEvent &p = pktEvents[pktHead];
      pktHead = (pktHead + 1) % PKT_SLOTS;
      p.seq = ++eventSeq;
      p.ms = millis();
      p.freqKhzX10 = acfg.freqKhzX10;
      p.sync1 = acfg.sync1;
      p.sync0 = acfg.sync0;
      p.len = acfg.pktlen;
      p.rssi = rawToDbm(buf[acfg.pktlen]);
      p.lqi = buf[acfg.pktlen + 1] & 0x7F;
      memcpy(p.data, buf, acfg.pktlen);
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SIDLE);
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SFRX);
      ELECHOUSE_cc1101.SpiStrobe(CC1101_SRX);
    }
    return;
  }
  // edge capture: track signal strength while a burst is in progress
  if (capLen) capMaxRssi = max((int)capMaxRssi, ELECHOUSE_cc1101.getRssi());
  portENTER_CRITICAL(&capMux);
  if (capLen && (micros() - lastEdgeUs) > acfg.endUs) finishCapture();
  volatile uint16_t *buf = capPending;
  uint16_t len = pendingLen;
  portEXIT_CRITICAL(&capMux);
  if (len) {
    if (capMaxRssi >= acfg.squelch) storeCapture(buf, len, capMaxRssi);
    capMaxRssi = -128;
    portENTER_CRITICAL(&capMux);
    pendingLen = 0;
    capPending = nullptr;
    portEXIT_CRITICAL(&capMux);
  }
}

static void analystConfigure() {
  detachInterrupt(digitalPinToInterrupt(PIN_GDO2[ANALYST]));
  if (!moduleOk[ANALYST]) return;
  ELECHOUSE_cc1101.setModul(ANALYST);
  ELECHOUSE_cc1101.Init();
  float mhz = acfg.freqKhzX10 / 10000.0f;
  if (acfg.mode == M_FSK_PKT || acfg.mode == M_OOK_PKT) {
    ELECHOUSE_cc1101.setCCMode(1);
    ELECHOUSE_cc1101.setModulation(acfg.mode == M_OOK_PKT ? 2 : 0);   // ASK/OOK or 2-FSK
    ELECHOUSE_cc1101.setMHZ(mhz);
    if (acfg.mode == M_FSK_PKT) ELECHOUSE_cc1101.setDeviation(acfg.dev);
    ELECHOUSE_cc1101.setDRate(acfg.drate);
    ELECHOUSE_cc1101.setRxBW(acfg.rxbw);
    ELECHOUSE_cc1101.setSyncMode(2);             // 16/16 sync bits
    ELECHOUSE_cc1101.setSyncWord(acfg.sync1, acfg.sync0);
    ELECHOUSE_cc1101.setPktFormat(0);
    ELECHOUSE_cc1101.setLengthConfig(0);         // fixed length
    ELECHOUSE_cc1101.setPacketLength(acfg.pktlen);
    ELECHOUSE_cc1101.setCrc(0);
    ELECHOUSE_cc1101.setWhiteData(0);
    ELECHOUSE_cc1101.setManchester(acfg.manchester ? 1 : 0);
    ELECHOUSE_cc1101.setAdrChk(0);
    ELECHOUSE_cc1101.setAppendStatus(1);
    ELECHOUSE_cc1101.SpiStrobe(CC1101_SIDLE);
    ELECHOUSE_cc1101.SpiStrobe(CC1101_SFRX);
    ELECHOUSE_cc1101.SetRx();
  } else if (acfg.mode != M_OFF) {
    // asynchronous serial mode: demodulated data on GDO2, as the stock firmware does
    ELECHOUSE_cc1101.setCCMode(0);
    if (acfg.mode == M_OOK) {
      ELECHOUSE_cc1101.setDcFilterOff(0);
      ELECHOUSE_cc1101.setModulation(2);         // ASK/OOK
    } else {
      ELECHOUSE_cc1101.setDcFilterOff(1);
      ELECHOUSE_cc1101.setModulation(0);         // 2-FSK
      ELECHOUSE_cc1101.setDeviation(acfg.dev);
    }
    ELECHOUSE_cc1101.setMHZ(mhz);
    ELECHOUSE_cc1101.setSyncMode(0);
    ELECHOUSE_cc1101.setPktFormat(3);
    ELECHOUSE_cc1101.setRxBW(acfg.rxbw);
    ELECHOUSE_cc1101.setDRate(acfg.drate);
    portENTER_CRITICAL(&capMux);
    capLen = 0;
    pendingLen = 0;
    capPending = nullptr;
    merging = false;
    portEXIT_CRITICAL(&capMux);
    capMaxRssi = -128;
    pinMode(PIN_GDO2[ANALYST], INPUT);
    ELECHOUSE_cc1101.SetRx();
    lastEdgeUs = micros();
    attachInterrupt(digitalPinToInterrupt(PIN_GDO2[ANALYST]), edgeIsr, CHANGE);
  } else {
    ELECHOUSE_cc1101.setSidle();
  }
}

// ---- small chunked JSON writer ------------------------------------------------
class Out {
 public:
  Out() { n = 0; }
  void begin(const char *type = "application/json") {
    server.sendHeader("Cache-Control", "no-store");
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200, type, "");
  }
  void raw(const char *s) {
    while (*s) {
      if (n >= sizeof(buf) - 1) flush();
      buf[n++] = *s++;
    }
  }
  void num(long v) {
    char t[16];
    snprintf(t, sizeof(t), "%ld", v);
    raw(t);
  }
  void hex(uint8_t b) {
    char t[3];
    snprintf(t, sizeof(t), "%02x", b);
    raw(t);
  }
  void fnum(float v, int digits = 1) {
    char t[24];
    snprintf(t, sizeof(t), "%.*f", digits, v);
    raw(t);
  }
  void flush() {
    if (n) {
      buf[n] = 0;
      server.sendContent(buf, n);
      n = 0;
    }
  }
  void end() {
    flush();
    server.sendContent("");
  }

 private:
  char buf[1400];
  size_t n;
};

static void sendJson(int code, const String &body) { server.send(code, "application/json", body); }

// ---- HTTP handlers ------------------------------------------------------------
static void handleInfo() {
  if (server.hasArg("dash")) {
    dashIp = server.client().remoteIP();
    dashPort = server.arg("dash").toInt();
  }
  Out o;
  o.begin();
  o.raw("{\"fw\":\"cc1101-nmap\",\"version\":\"" FW_VERSION "\",\"receive_only\":true,\"modules\":[");
  o.raw(moduleOk[0] ? "true," : "false,");
  o.raw(moduleOk[1] ? "true" : "false");
  o.raw("],\"hunter\":1,\"analyst\":2,\"max_points\":");
  o.num(MAX_POINTS);
  o.raw(",\"points\":");
  o.num(nPoints);
  o.raw(",\"seq\":");
  o.num(eventSeq);
  o.raw(",\"uptime_ms\":");
  o.num(millis());
  o.raw(",\"ip\":\"");
  o.raw((WiFi.getMode() == WIFI_AP ? WiFi.softAPIP() : WiFi.localIP()).toString().c_str());
  o.raw("\",\"free_heap\":");
  o.num(ESP.getFreeHeap());
  o.raw("}");
  o.end();
}

static void handlePlan() {
  String segs = server.arg("segments");
  if (server.hasArg("dwell_us")) dwellUs = constrain(server.arg("dwell_us").toInt(), 50, 5000);
  if (server.hasArg("reads")) readsPerPoint = constrain(server.arg("reads").toInt(), 1, 16);
  int n = 0;
  int start = 0;
  while (start < (int)segs.length() && n < MAX_POINTS) {
    int comma = segs.indexOf(',', start);
    if (comma < 0) comma = segs.length();
    String s = segs.substring(start, comma);
    start = comma + 1;
    float v[4] = {0, 0, 0, 270};
    int field = 0, p = 0;
    while (field < 4 && p <= (int)s.length()) {
      int colon = s.indexOf(':', p);
      if (colon < 0) colon = s.length();
      v[field++] = s.substring(p, colon).toFloat();
      p = colon + 1;
    }
    if (field < 2 || v[0] <= 0) continue;
    double a = v[0], b = v[1] < v[0] ? v[0] : v[1], step = v[2];
    int count = step > 0 ? (int)((b - a) / step + 1e-6) + 1 : 1;
    for (int k = 0; k < count && n < MAX_POINTS; k++) {
      planHz[n] = (uint32_t)((a + k * step) * 1000.0 + 0.5);
      planBw[n] = (uint16_t)v[3];
      peakDbm[n] = lastPeak[n] = lastAvg[n] = -128;
      sumDbm[n] = 0;
      cntDbm[n] = 0;
      n++;
    }
  }
  nPoints = n;
  cursorPt = 0;
  sweepsDone = 0;
  currentBw = 0;
  sweepStartMs = millis();
  sendJson(200, String("{\"ok\":true,\"points\":") + n + "}");
}

static void handleSpectrum() {
  Out o;
  o.begin();
  o.raw("{\"ok\":true,\"sweeps\":");
  o.num(sweepsDone);
  o.raw(",\"sweep_ms\":");
  o.num(lastSweepMs);
  o.raw(",\"freq_hz\":[");
  for (int i = 0; i < nPoints; i++) {
    if (i) o.raw(",");
    o.num(planHz[i]);
  }
  o.raw("],\"rxbw_khz\":[");
  for (int i = 0; i < nPoints; i++) {
    if (i) o.raw(",");
    o.num(planBw[i]);
  }
  o.raw("],\"peak\":[");
  for (int i = 0; i < nPoints; i++) {
    if (cntDbm[i]) lastPeak[i] = peakDbm[i];
    if (i) o.raw(",");
    o.num(lastPeak[i]);
  }
  o.raw("],\"avg\":[");
  for (int i = 0; i < nPoints; i++) {
    if (cntDbm[i]) lastAvg[i] = (int8_t)(sumDbm[i] / cntDbm[i]);
    if (i) o.raw(",");
    o.num(lastAvg[i]);
    peakDbm[i] = -128;
    sumDbm[i] = 0;
    cntDbm[i] = 0;
  }
  o.raw("]}");
  o.end();
  sweepsDone = 0;
}

static void handleRx() {
  if (server.arg("module") != "2") {
    sendJson(400, "{\"ok\":false,\"error\":\"module 1 is reserved for the RSSI sweep\"}");
    return;
  }
  String m = server.arg("mode");
  acfg.mode = m == "ook" ? M_OOK
            : m == "fsk_raw" ? M_FSK_RAW
            : m == "fsk_pkt" ? M_FSK_PKT
            : m == "ook_pkt" ? M_OOK_PKT : M_OFF;
  acfg.freqKhzX10 = (uint32_t)(server.arg("freq_khz").toFloat() * 10.0f + 0.5f);
  if (server.hasArg("rxbw_khz")) acfg.rxbw = server.arg("rxbw_khz").toFloat();
  if (server.hasArg("drate")) acfg.drate = server.arg("drate").toFloat();
  if (server.hasArg("dev_khz")) acfg.dev = server.arg("dev_khz").toFloat();
  acfg.manchester = server.hasArg("manchester") && server.arg("manchester") == "1";
  acfg.minUs = server.hasArg("min_us") ? constrain(server.arg("min_us").toInt(), 5, 2000) : 60;
  acfg.endUs = server.hasArg("end_us") ? constrain(server.arg("end_us").toInt(), 1000, 60000) : 15000;
  if (server.hasArg("squelch")) acfg.squelch = constrain(server.arg("squelch").toInt(), -128, 0);
  if (server.hasArg("pktlen")) acfg.pktlen = constrain(server.arg("pktlen").toInt(), 1, 62);
  if (server.hasArg("sync") && server.arg("sync").length() == 4) {
    long s = strtol(server.arg("sync").c_str(), nullptr, 16);
    acfg.sync1 = (s >> 8) & 0xFF;
    acfg.sync0 = s & 0xFF;
  }
  float mhz = acfg.freqKhzX10 / 10000.0f;
  if (acfg.mode == M_OFF || mhz < 280 || mhz > 965) {
    acfg.mode = M_OFF;
    analystConfigure();
    sendJson(400, "{\"ok\":false,\"error\":\"bad mode or frequency\"}");
    return;
  }
  analystConfigure();
  sendJson(200, "{\"ok\":true}");
}

static void handleEvents() {
  uint32_t since = server.hasArg("since") ? strtoul(server.arg("since").c_str(), nullptr, 10) : 0;
  Out o;
  o.begin();
  o.raw("{\"seq\":");
  o.num(eventSeq);
  o.raw(",\"now_ms\":");
  o.num(millis());
  o.raw(",\"dropped\":");
  o.num(droppedEvents);
  droppedEvents = 0;
  o.raw(",\"captures\":[");
  bool first = true;
  for (int k = 0; k < CAP_SLOTS; k++) {
    CapEvent &e = capEvents[(capHead + k) % CAP_SLOTS];
    if (!e.seq || e.seq <= since) continue;
    if (!first) o.raw(",");
    first = false;
    o.raw("{\"seq\":");
    o.num(e.seq);
    o.raw(",\"ms\":");
    o.num(e.ms);
    o.raw(",\"freq_khz\":");
    o.fnum(e.freqKhzX10 / 10.0f);
    o.raw(",\"mode\":\"");
    o.raw(MODE_NAMES[e.mode]);
    o.raw("\",\"rssi\":");
    o.num(e.rssi);
    o.raw(",\"pulses\":[");
    for (uint16_t i = 0; i < e.len; i++) {
      if (i) o.raw(",");
      o.num(e.data[i]);
    }
    o.raw("]}");
  }
  o.raw("],\"packets\":[");
  first = true;
  for (int k = 0; k < PKT_SLOTS; k++) {
    PktEvent &p = pktEvents[(pktHead + k) % PKT_SLOTS];
    if (!p.seq || p.seq <= since) continue;
    if (!first) o.raw(",");
    first = false;
    o.raw("{\"seq\":");
    o.num(p.seq);
    o.raw(",\"ms\":");
    o.num(p.ms);
    o.raw(",\"freq_khz\":");
    o.fnum(p.freqKhzX10 / 10.0f);
    o.raw(",\"sync\":\"");
    o.hex(p.sync1);
    o.hex(p.sync0);
    o.raw("\",\"rssi\":");
    o.num(p.rssi);
    o.raw(",\"lqi\":");
    o.num(p.lqi);
    o.raw(",\"hex\":\"");
    for (uint8_t i = 0; i < p.len; i++) o.hex(p.data[i]);
    o.raw("\"}");
  }
  o.raw("]}");
  o.end();
}

static void handleRoot() {
  String ip = (WiFi.getMode() == WIFI_AP ? WiFi.softAPIP() : WiFi.localIP()).toString();
  String html = F("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                  "<title>cc1101-nmap</title><style>body{font:15px system-ui,sans-serif;margin:0;padding:24px;background:#0f1216;color:#e7ebf0}"
                  "main{max-width:640px;margin:auto}a.btn{display:inline-block;background:#5ab0ff;color:#06121f;padding:12px 18px;border-radius:8px;"
                  "text-decoration:none;font-weight:600}code{background:#1d222a;padding:2px 6px;border-radius:4px}td{padding:4px 12px 4px 0}"
                  ".muted{color:#96a0ad}</style></head><body><main><h1>cc1101-nmap</h1>"
                  "<p class=muted>Receive-only sub-GHz scanner firmware for the Evil Crow RF V2.</p>");
  if (dashPort) {
    String url = "http://" + dashIp.toString() + ":" + String(dashPort) + "/";
    html += "<p><a class=btn href='" + url + "'>Open the dashboard: what's near</a></p><p class=muted>" + url + "</p>";
  } else {
    html += "<p>No scanner connected yet. On your Raspberry Pi or PC run:</p><p><code>python3 -m cc1101nmap --host " + ip +
            "</code></p><p class=muted>The dashboard link appears here once it connects.</p>";
  }
  html += "<table><tr><td>Firmware</td><td>" FW_VERSION "</td></tr><tr><td>Module 1 (sweep)</td><td>" +
          String(moduleOk[0] ? "ok" : "not found") + "</td></tr><tr><td>Module 2 (capture)</td><td>" +
          String(moduleOk[1] ? "ok" : "not found") + "</td></tr><tr><td>Sweep</td><td>" + String(nPoints) + " channels, " +
          String(lastSweepMs) + " ms</td></tr><tr><td>Listening</td><td>" + String(MODE_NAMES[acfg.mode]) + " " +
          String(acfg.freqKhzX10 / 10000.0f, 3) + " MHz</td></tr><tr><td>Address</td><td>" + ip + " / " + HOSTNAME +
          ".local</td></tr></table></main></body></html>";
  server.send(200, "text/html", html);
}

// ---- setup ----------------------------------------------------------------------
static bool readWifiConfig(String &ssid, String &pass) {
  SPIClass sdspi(HSPI);
  sdspi.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  bool ok = false;
  if (SD.begin(SD_CS, sdspi) && SD.exists("/wifi_config.txt")) {
    File f = SD.open("/wifi_config.txt", FILE_READ);
    if (f) {
      ssid = f.readStringUntil('\n');
      pass = f.readStringUntil('\n');
      ssid.trim();
      pass.trim();
      f.close();
      ok = ssid.length() > 0;
    }
  }
  SD.end();
  sdspi.end();
  return ok;
}

static bool joinWifi(const String &ssid, const String &pass) {
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(HOSTNAME);
  WiFi.begin(ssid.c_str(), pass.c_str());
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) delay(250);
  return WiFi.status() == WL_CONNECTED;
}

void setup() {
  Serial.begin(115200);
  String ssid, pass;
  bool joined = false;
  if (readWifiConfig(ssid, pass)) joined = joinWifi(ssid, pass);
  if (!joined) joined = joinWifi(STOCK_SSID, STOCK_PASS);
  if (!joined) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
  }
  MDNS.begin(HOSTNAME);
  MDNS.addService("http", "tcp", 80);

  ELECHOUSE_cc1101.addSpiPin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CS[0], 0);
  ELECHOUSE_cc1101.addSpiPin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CS[1], 1);
  for (int m = 0; m < 2; m++) {
    ELECHOUSE_cc1101.setModul(m);
    moduleOk[m] = ELECHOUSE_cc1101.getCC1101();
    if (moduleOk[m]) {
      ELECHOUSE_cc1101.Init();
      ELECHOUSE_cc1101.setModulation(2);
      ELECHOUSE_cc1101.setMHZ(433.92);
      ELECHOUSE_cc1101.setSidle();
    }
  }
  analystConfigure();

  server.on("/", HTTP_GET, handleRoot);
  server.on("/nmap/info", HTTP_GET, handleInfo);
  server.on("/nmap/plan", HTTP_POST, handlePlan);
  server.on("/nmap/spectrum", HTTP_GET, handleSpectrum);
  server.on("/nmap/rx", HTTP_POST, handleRx);
  server.on("/nmap/events", HTTP_GET, handleEvents);
  server.onNotFound([]() { server.send(404, "text/plain", "not found"); });
  server.begin();
  Serial.printf("cc1101-nmap %s ready at http://%s/ (modules: %d %d)\n", FW_VERSION,
                (joined ? WiFi.localIP() : WiFi.softAPIP()).toString().c_str(), moduleOk[0], moduleOk[1]);
}

void loop() {
  server.handleClient();
  analystService();
  hunterStep(8);      // ~10 ms of sweeping between HTTP/capture servicing
  analystService();
}
