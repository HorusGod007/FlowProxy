#pragma once

#include "net/socket.h"
#include <string>

// SOCKS4 connect through an already-connected socket to the SOCKS proxy
bool socks4_connect(Socket& sock, const std::string& dest_host, uint16_t dest_port,
                    const std::string& userid = "");

// SOCKS5 connect with optional authentication
bool socks5_connect(Socket& sock, const std::string& dest_host, uint16_t dest_port,
                    const std::string& username = "", const std::string& password = "");
