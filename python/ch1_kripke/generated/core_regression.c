/* Generated baseline regression tests. Review before use as an oracle. */
#include "state_machine.h"
#include <stdio.h>
int main(void) {
int failures = 0; client_state_t next; bool accepted;
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != true || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL IDLE / ACCEPT"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / LOGIN_OK"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / LOGIN_FAIL"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / JOIN_OK"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / JOIN_FAIL"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / LEAVE_OK"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / ROOM_CLOSED"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != false || next != STATE_IDLE) {
puts("FAIL IDLE / LOGOUT"); ++failures; }
next = STATE_IDLE;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != true || next != STATE_CLOSED) {
puts("FAIL IDLE / DISCONNECT"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / ACCEPT"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != true || next != STATE_WS_CONNECTED) {
puts("FAIL HTTP_HANDSHAKE / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / LOGIN_OK"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / LOGIN_FAIL"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / JOIN_OK"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / JOIN_FAIL"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / LEAVE_OK"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / ROOM_CLOSED"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != false || next != STATE_HTTP_HANDSHAKE) {
puts("FAIL HTTP_HANDSHAKE / LOGOUT"); ++failures; }
next = STATE_HTTP_HANDSHAKE;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != true || next != STATE_CLOSED) {
puts("FAIL HTTP_HANDSHAKE / DISCONNECT"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / ACCEPT"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != true || next != STATE_AUTHENTICATED) {
puts("FAIL WS_CONNECTED / LOGIN_OK"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != true || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / LOGIN_FAIL"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / JOIN_OK"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / JOIN_FAIL"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / LEAVE_OK"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / ROOM_CLOSED"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != false || next != STATE_WS_CONNECTED) {
puts("FAIL WS_CONNECTED / LOGOUT"); ++failures; }
next = STATE_WS_CONNECTED;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != true || next != STATE_CLOSED) {
puts("FAIL WS_CONNECTED / DISCONNECT"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / ACCEPT"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / LOGIN_OK"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / LOGIN_FAIL"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != true || next != STATE_IN_ROOM) {
puts("FAIL AUTHENTICATED / JOIN_OK"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != true || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / JOIN_FAIL"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / LEAVE_OK"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != false || next != STATE_AUTHENTICATED) {
puts("FAIL AUTHENTICATED / ROOM_CLOSED"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != true || next != STATE_WS_CONNECTED) {
puts("FAIL AUTHENTICATED / LOGOUT"); ++failures; }
next = STATE_AUTHENTICATED;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != true || next != STATE_CLOSED) {
puts("FAIL AUTHENTICATED / DISCONNECT"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / ACCEPT"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / LOGIN_OK"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / LOGIN_FAIL"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / JOIN_OK"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / JOIN_FAIL"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != true || next != STATE_AUTHENTICATED) {
puts("FAIL IN_ROOM / LEAVE_OK"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != true || next != STATE_AUTHENTICATED) {
puts("FAIL IN_ROOM / ROOM_CLOSED"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != false || next != STATE_IN_ROOM) {
puts("FAIL IN_ROOM / LOGOUT"); ++failures; }
next = STATE_IN_ROOM;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != true || next != STATE_CLOSED) {
puts("FAIL IN_ROOM / DISCONNECT"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_ACCEPT);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / ACCEPT"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_HTTP_UPGRADE_OK);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / HTTP_UPGRADE_OK"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_OK);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / LOGIN_OK"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGIN_FAIL);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / LOGIN_FAIL"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_OK);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / JOIN_OK"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_JOIN_FAIL);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / JOIN_FAIL"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_LEAVE_OK);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / LEAVE_OK"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_ROOM_CLOSED);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / ROOM_CLOSED"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_LOGOUT);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / LOGOUT"); ++failures; }
next = STATE_CLOSED;
accepted = client_state_apply(&next, CLIENT_EVENT_DISCONNECT);
if (accepted != false || next != STATE_CLOSED) {
puts("FAIL CLOSED / DISCONNECT"); ++failures; }
printf("Core snapshot regression: %d failures\n", failures);
return failures ? 1 : 0;
}
