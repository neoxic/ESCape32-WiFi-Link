/*
** Copyright (C) 2023 Arseny Vakhrushev <arseny.vakhrushev@me.com>
**
** This firmware is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** This firmware is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this firmware. If not, see <http://www.gnu.org/licenses/>.
*/

#include "nvs_flash.h"
#include "esp_crc.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "lwip/sockets.h"
#include "mdns.h"

#define SSID "ESCape32-WiFi-Link"
#define HOSTNAME "escape32"

#define CMD_PROBE  0
#define CMD_INFO   1
#define CMD_READ   2
#define CMD_WRITE  3
#define CMD_UPDATE 4
#define CMD_SETWRP 5

typedef struct __attribute__((__packed__)) {
	uint16_t xid;
	uint16_t flags;
	uint16_t qucnt;
	uint16_t ancnt;
	uint16_t nscnt;
	uint16_t arcnt;
} DNSHeader;

typedef struct __attribute__((__packed__)) {
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t len;
	uint32_t addr;
} DNSAnswer;

extern const char _binary_root_html_gz_start[];
extern const char _binary_root_html_gz_end[];

static httpd_handle_t server;
static QueueHandle_t queue;

static void setled(int x) {
#ifdef CONFIG_LED_INV
	x = !x;
#endif
	gpio_set_level(CONFIG_LED_PIN, x);
}

int processdns(uint8_t *buf, int len) {
	if (len < (int)sizeof(DNSHeader)) return 0;
	DNSHeader *header = (DNSHeader *)buf;
	int flags = ntohs(header->flags);
	if (flags & 0x7800) return 0; // Check for OPCODE=0
	uint8_t *cur = buf + sizeof *header;
	uint8_t *end = buf + len;
	uint8_t *pos = end;
	int cnt = 0;
	for (int i = 0, n = ntohs(header->qucnt); i < n; ++i) {
		uint8_t *name = cur;
		for (int s; cur < end && (s = *cur++); cur += s);
		if (cur + 4 > end) return 0;
		int type = ntohs(*(uint16_t *)cur);
		int class = ntohs(*(uint16_t *)(cur + 2));
		cur += 4;
		if (type != 1 || class != 1) continue;
		DNSAnswer *answer = (DNSAnswer *)pos;
		pos += sizeof *answer;
		if (pos - buf > 512) return 0;
		answer->name = htons(0xc000 | (name - buf));
		answer->type = htons(type);
		answer->class = htons(class);
		answer->ttl = htonl(60);
		answer->len = htons(4);
		answer->addr = htonl(0xc0a80401); // 192.168.4.1
		++cnt;
	}
	memmove(cur, end, pos - end); // Ignore other sections
	header->flags = htons(flags | 0x8000); // Set QR
	header->ancnt = htons(cnt);
	header->nscnt = 0;
	header->arcnt = 0;
	return pos - end + cur - buf;
}

static int recvbuf(uint8_t *buf, int len, int all) {
	int ofs = 0;
	while (len) {
		size_t size;
		uart_get_buffered_data_len(CONFIG_UART_NUM, &size);
		if (!size) {
			setled(1);
			uart_event_t event;
			if (!xQueueReceive(queue, &event, 200 / portTICK_PERIOD_MS) || event.type != UART_DATA) { // I/O error
				setled(0);
				return 0;
			}
			size = event.size;
			setled(0);
		}
		if (size > len) size = len;
		uart_read_bytes(CONFIG_UART_NUM, buf, size, portMAX_DELAY);
		buf += size;
		ofs += size;
		len -= size;
		if (all) continue;
		if (ofs >= 3 && !memcmp(buf - 3, "OK\n", 3)) break;
		if (ofs >= 6 && !memcmp(buf - 6, "ERROR\n", 6)) break;
	}
	return ofs;
}

static void sendbuf(const uint8_t *buf, int len) {
	xQueueReset(queue);
	uart_flush(CONFIG_UART_NUM);
	uart_write_bytes(CONFIG_UART_NUM, buf, len);
}

static int recvval(void) {
	uint8_t buf[2];
	return recvbuf(buf, 2, 1) && (buf[0] ^ buf[1]) == 0xff ? buf[0] : -1;
}

static void sendval(int val) {
	uint8_t buf[2] = {val, ~val};
	sendbuf(buf, 2);
}

static int recvdata(uint8_t *buf) {
	int cnt = recvval();
	if (cnt == -1) return -1;
	int len = (cnt + 1) << 2;
	uint32_t crc;
	return recvbuf(buf, len, 1) && recvbuf((uint8_t *)&crc, 4, 1) && esp_crc32_le(0, buf, len) == crc ? len : -1;
}

static void senddata(const uint8_t *buf, int len) {
	uint32_t crc = esp_crc32_le(0, buf, len);
	sendval((len >> 2) - 1);
	sendbuf(buf, len);
	sendbuf((uint8_t *)&crc, 4);
}

static char *checkcmd(uint8_t *buf, int len, const char *cmd) {
	int n = strlen(cmd);
	return len < n || memcmp(buf, cmd, n) || (buf[n] != ' ' && buf[n] != '\n') ? 0 : (char *)buf + n;
}

static int maxlen(int pos, int size) {
	int len = size - pos;
	if (len > 1024) len = 1024;
	return len;
}

static void notify(httpd_req_t *req, const char *key, int val) {
	char buf[32];
	httpd_ws_frame_t frame = {
		.type = HTTPD_WS_TYPE_TEXT,
		.payload = (uint8_t *)buf,
		.len = sprintf(buf, "%s %d\n", key, val),
	};
	httpd_ws_send_frame(req, &frame);
}

static esp_err_t http404handler(httpd_req_t *req, httpd_err_code_t err) {
	httpd_resp_set_status(req, "302 Temporary Redirect");
	httpd_resp_set_hdr(req, "Location", "/");
	httpd_resp_send(req, "Redirect", 8);
	return 0;
}

static esp_err_t roothandler(httpd_req_t *req) {
	httpd_resp_set_type(req, "text/html");
	httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
	httpd_resp_send(req, _binary_root_html_gz_start, _binary_root_html_gz_end - _binary_root_html_gz_start);
	return 0;
}

static esp_err_t wshandler(httpd_req_t *req) {
	static int size, boot, wrp;
	if (req->method == HTTP_GET) return 0;
	httpd_ws_frame_t frame = {0};
	if (httpd_ws_recv_frame(req, &frame, 0)) return -1;
	int len = frame.len;
	int res = -1;
	switch (frame.type) {
		case HTTPD_WS_TYPE_TEXT: { // CLI passthrough
			uint8_t buf[1200];
			frame.payload = buf;
			if (httpd_ws_recv_frame(req, &frame, sizeof buf)) return -1;
			char *arg;
			if ((arg = checkcmd(buf, len, "_probe"))) {
				if (*arg != '\n') goto done;
				sendval(CMD_PROBE);
				res = recvval();
				goto done;
			}
			if ((arg = checkcmd(buf, len, "_info"))) {
				if (*arg != '\n') goto done;
				uint8_t info[52];
				sendval(CMD_INFO);
				if (recvdata(info) != 32) goto done;
				sendval(CMD_READ);
				sendval(0); // First block
				sendval(4); // (4+1)*4=20 bytes
				if (recvdata(info + 32) != 20) goto done;
				len += sprintf((char *)buf + len, "%d %d %X\n", info[0], info[1], info[2] | info[3] << 8 | info[4] << 16 | info[5] << 24);
				len += sprintf((char *)buf + len, info[32] == 0xea && info[33] == 0x32 ? "%d\n%s\n" : "\n\n", info[34], info + 36);
				res = 0;
				goto done;
			}
			if ((arg = checkcmd(buf, len, "_setwrp"))) {
				int val = strtol(arg, &arg, 0);
				if (*arg != '\n') goto done;
				sendval(CMD_SETWRP);
				sendval(val);
				res = recvval();
				goto done;
			}
			if ((arg = checkcmd(buf, len, "_update"))) {
				size = strtol(arg, &arg, 0);
				boot = strtol(arg, &arg, 0);
				wrp = strtol(arg, &arg, 0);
				if (*arg != '\n') goto done;
				res = 0;
				goto done;
			}
			sendbuf(buf, len);
			if (checkcmd(buf, len, "play")) return 0; // Don't wait for response
			int ofs = recvbuf(buf + len, sizeof buf - len, 0);
			if (!ofs) return -1;
			frame.len += ofs;
			return httpd_ws_send_frame(req, &frame);
		done:
			len += sprintf((char *)buf + len, res ? "ERROR\n" : "OK\n");
			frame.len = len;
			return httpd_ws_send_frame(req, &frame);
		}
		case HTTPD_WS_TYPE_BINARY: { // Firmware update
			if (size != len || !(size = (size + 3) & ~3) || (boot && size > 4096)) {
				ESP_LOGE("httpd_ws", "Invalid image size %d (payload %zu)", size, len);
				return -1;
			}
			uint8_t *buf = malloc(size);
			if (!buf) {
				ESP_LOGE("httpd_ws", "Can't allocate %d bytes", size);
				return -1;
			}
			frame.payload = memset(buf, 0xff, size);
			if (httpd_ws_recv_frame(req, &frame, len)) {
				free(buf);
				return -1;
			}
			ESP_LOGI("httpd_ws", "Firmware update started (size %d, boot %d, wrp 0x%02x)", size, boot, wrp);
			if (boot) {
				if (!(size & 1023) && size != 4096) size += 4; // Ensure last block marker
				sendval(CMD_UPDATE);
				for (int pos = 0; pos < size; pos += 1024) {
					notify(req, "_status", pos * 100 / size);
					senddata(buf + pos, maxlen(pos, size));
					if ((res = recvval())) break;
				}
				if (!res) res = recvval(); // Wait for ACK after reboot
			} else {
				for (int pos = 0; pos < size; pos += 1024) {
					notify(req, "_status", pos * 100 / size);
					sendval(CMD_WRITE);
					sendval(pos / 1024); // Block number
					senddata(buf + pos, maxlen(pos, size));
					if ((res = recvval())) break;
				}
			}
			if (!res) {
				notify(req, "_status", 100);
				if (wrp) {
					sendval(CMD_SETWRP);
					sendval(wrp);
					res = recvval();
				}
			}
			notify(req, "_result", res);
			ESP_LOGI("httpd_ws", "Firmware update completed with result %d", res);
			free(buf);
			return 0;
		}
		default:
			ESP_LOGE("httpd_ws", "Unrecognized frame type %d", frame.type);
			return -1;
	}
}

static void addhandler(const char *path, esp_err_t (*handler)(httpd_req_t *)) {
	const httpd_uri_t uri = {
		.uri = path,
		.method = HTTP_GET,
		.handler = handler,
		.is_websocket = handler == wshandler,
	};
	ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri));
}

static void connhandler(void *arg, esp_event_base_t base, int32_t id, void *data) {
	ESP_LOGI("httpd", "Socket %d connected", *(int *)data);
}

static void disconnhandler(void *arg, esp_event_base_t base, int32_t id, void *data) {
	ESP_LOGI("httpd", "Socket %d disconnected", *(int *)data);
}

void app_main(void) {
	gpio_set_direction(CONFIG_LED_PIN, GPIO_MODE_OUTPUT);
	setled(1);

	esp_log_level_set("httpd_uri", ESP_LOG_ERROR);
	esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
	esp_log_level_set("httpd_parse", ESP_LOG_ERROR);

	ESP_ERROR_CHECK(nvs_flash_init());
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_ap();

	wifi_init_config_t wicfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&wicfg));

	wifi_config_t wcfg = {
		.ap = {
			.ssid = SSID,
			.ssid_len = sizeof SSID - 1,
			.max_connection = 1,
			.authmode = WIFI_AUTH_OPEN,
		},
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wcfg));
	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_ERROR_CHECK(mdns_init());
	ESP_ERROR_CHECK(mdns_hostname_set(HOSTNAME));

	uart_config_t ucfg = {
		.baud_rate = 38400,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};
	ESP_ERROR_CHECK(uart_driver_install(CONFIG_UART_NUM, UART_HW_FIFO_LEN(CONFIG_UART_NUM) * 2, 0, 10, &queue, 0));
	ESP_ERROR_CHECK(uart_param_config(CONFIG_UART_NUM, &ucfg));
	ESP_ERROR_CHECK(uart_set_pin(CONFIG_UART_NUM, CONFIG_UART_TX, CONFIG_UART_RX, -1, -1));
	ESP_ERROR_CHECK(uart_set_mode(CONFIG_UART_NUM, UART_MODE_RS485_HALF_DUPLEX));

	httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
	hcfg.max_open_sockets = CONFIG_LWIP_MAX_SOCKETS - 3;
	hcfg.lru_purge_enable = true;
	ESP_ERROR_CHECK(httpd_start(&server, &hcfg));
	ESP_ERROR_CHECK(httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http404handler));
	addhandler("/", roothandler);
	addhandler("/ws", wshandler);

	ESP_ERROR_CHECK(esp_event_handler_register(ESP_HTTP_SERVER_EVENT, HTTP_SERVER_EVENT_ON_CONNECTED, &connhandler, 0));
	ESP_ERROR_CHECK(esp_event_handler_register(ESP_HTTP_SERVER_EVENT, HTTP_SERVER_EVENT_DISCONNECTED, &disconnhandler, 0));

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		ESP_LOGE("dns", "socket() failed: %s", strerror(errno));
		return;
	}
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(53),
	};
	socklen_t sl = sizeof sa;
	if (bind(fd, (struct sockaddr *)&sa, sl) == -1) {
		ESP_LOGE("dns", "bind() failed: %s", strerror(errno));
		close(fd);
		return;
	}
	setled(0);
	for (;;) {
		uint8_t buf[512];
		int len1 = recvfrom(fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&sa, &sl);
		if (len1 == -1) {
			ESP_LOGE("dns", "recvfrom() failed: %s", strerror(errno));
			break;
		}
		int len2 = processdns(buf, len1);
		if (!len2) {
			ESP_LOGE("dns", "Can't process request (%d bytes)", len1);
			continue;
		}
		if (sendto(fd, buf, len2, 0, (struct sockaddr *)&sa, sl) == -1) {
			ESP_LOGE("dns", "sendto() failed: %s", strerror(errno));
			continue;
		}
		ESP_LOGI("dns", "Processed request (%d bytes -> %d bytes)", len1, len2);
	}
	close(fd);
}
