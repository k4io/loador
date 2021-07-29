#include "includes.h"

void WelcomePrint()
{
	SetConsoleTitleW(L"[LOS]");
	ccolor(MAGENTA, BLACK);
	//printf("[LOS] ");
	ccolor(RED, BLACK);
	printf(R"(   __         ______     ______   
  /\ \       /\  __ \   /\  ___\  
  \ \ \____  \ \ \/\ \  \ \___  \ 
   \ \_____\  \ \_____\  \/\_____\
    \/_____/   \/_____/   \/_____/
                                  )");
	ccolor(WHITE, BLACK);
	printf("\n > ");
	ccolor(GREEN, BLACK);
	printf("Welcome!\n\n");
	ccolor(WHITE, BLACK);
}

bool connect()
{
	WSAData w;
	int sockfd = 0;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &w);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	char name[BuffSize];
	char request[BuffSize];
	char response[BuffSize];

	const SSL_METHOD* method = TLSv1_2_client_method();
	if (NULL == method) report_and_exit("TLSv1_2_client_method was NULL");

	SSL_CTX* ctx = SSL_CTX_new(method);
	if (NULL == ctx) report_and_exit("SSL_CTX_new was NULL");

	bio = BIO_new_ssl_connect(ctx);
	if (NULL == bio) report_and_exit("BIO_new_ssl_connect was NULL");

	ssl = NULL;
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	//get host ip
	std::ostringstream strout;
	struct hostent* h = gethostbyname("host.fuckabitch.net");
	unsigned char* addr = reinterpret_cast<unsigned char*>(h->h_addr_list[0]);
	std::copy(addr, addr + 4, std::ostream_iterator<unsigned int>(strout, "."));
	std::string ip = strout.str();
	ip = ip.substr(0, ip.length() - 1);
	sprintf(name, "%s:51005", ip.c_str());

	BIO_set_conn_hostname(bio, name);

	if (BIO_do_connect(bio) <= 0) {
		cleanup(ctx, bio);
		return false;
	}

	sprintf(request, "H-C");
	sendpacket(bio, request); //Send client hello identifier to server
	memset(response, '\0', sizeof(response));
	int n = receivepacket(bio, response);
	if (n <= 0)
	{
		ccolor(RED, BLACK);
		printf("\nthere was an error\nplease contact kaio#7754");
		report_and_exit("error when sending hello!");
	}

	std::string r(response);
	while (1)
	{
		SleepEx(150, 0);
		ccolor(WHITE, BLACK);
		printf("\n > ");
		ccolor(GREEN, BLACK);
		printf("Connected!\n");
		ccolor(WHITE, BLACK);
		printf("\n # ");
		ccolor(YELLOW, BLACK);
		printf("Username: ");
		ccolor(WHITE, BLACK);
		std::string username = "";
		std::cin >> username;
		std::string password_str = getpass();
		sendpacket(bio, "R-C");
		memset(&response, '\x00', 512);
		receivepacket(bio, response);
		if (response[7] == '\xB6')
		{
			//send login packet (username:hwid:ver)
			std::string infopacket = "L|" + username + "|" + info() + "|1.0";
			sendpacket(bio, infopacket);
			receivepacket(bio, response);
			if (response[7] == '\xB7') {
				break;
			}
			else
			{
				ccolor(RED, BLACK);
				printf("\nError, incorrect username & password combination!\n\n");
				SleepEx(500, 0);
			}
		}
		else
		{
			ccolor(RED, BLACK);
			printf("\nError while receiving ready from server!\n\n");
			SleepEx(500, 0);
		}
	}
	std::string rstr = std::string(response);
	std::string instr = rstr.substr(1, rstr.size());
	int k = std::stoi(instr);
	authkey = k;
	printf("\nReceived challenge!\n");
	return true;
}

int main()
{
	WelcomePrint();
	ccolor(WHITE, BLACK);
	printf(" > ");
	ccolor(GREEN, BLACK);
	printf("Connecting ");
	ccolor(WHITE, BLACK);
	std::cout << '-' << std::flush;
	while (!connected)
	{
		if (connect())
		{
			char *response = new char[512];
			//get all modules for account and display
			sendpacket(bio, "R-M");
			receivepacket(bio, response);
			std::string rs(response);
			std::vector<std::string> modules = explode(response, '|');
			int sz = modules.size();
			ccolor(WHITE, BLACK);
			printf("\nModules:\n");
			ccolor(YELLOW, BLACK);
			for (size_t i = 0; i < modules.size() - 1; i++)
			{
				std::string l = "\t" + std::to_string(i) + ": " + modules[i] + "\n";
				ccolor(MAGENTA, BLACK);
				printf("\t%i", i);
				ccolor(WHITE, BLACK);
				printf(": %s\n", modules[i]);
			}
			int mod = -1;
			while (mod == -1)
			{
				ccolor(WHITE, BLACK);
				printf("\n > Load module: ");
				ccolor(GREEN, BLACK);
				int n = 0;
				std::cin >> n;
				if (n > sz || n < sz)
				{
					continue;
				}
				else
				{
					mod = n;
					break;
				}
			}
			ccolor(WHITE, BLACK);
			printf("\n > Downloading ");
			ccolor(GREEN, BLACK);
			printf("%s");
			ccolor(WHITE, BLACK);
			printf(" DLL...");

			std::string npacket = "R-M-" + modules[mod];
			sendpacket(bio, npacket);
			memset(&response, '\x00', 512);
			receivepacket(bio, response);

			if (response[0] == '\x11')
			{
				ccolor(RED, BLACK);
				printf("\nError, you do not have access to this module!");
				SleepEx(3000, 0);
				exit(-1);
			}

			//download the module
			int filesize = 0;
			memset(&response, '\x00', 512);
			receivepacket(bio, response);
			std::string r_str(response);
			std::string fs_str = r_str.substr(0, 31);
			std::string process_name = r_str.substr(255, 511);
			filesize = std::stoi(fs_str);

			std::vector<char> filearray{};
			for (size_t i = 0; i < (filesize / BuffSize) + 1; i++)
			{
				for (size_t j = 0; j < BuffSize; j++)
					response[j] = 0;

				receivepacket(bio, response);

				for (size_t j = 0; j < BuffSize; j++)
					filearray.push_back(response[j]);
			}

			DWORD _pid = getProcess(process_name);

			HANDLE _hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pid);

			if (!_hProc)
			{
				printf("There was an error with OpenProcess: 0x%X\n", std::to_string(GetLastError()));
				SleepEx(3000, 0);
				return 0;
			}

			if (!_map(_hProc, &filearray))
			{
				CloseHandle(_hProc);
				printf("Manual mapping failed with code: 0x%X\n", std::to_string(GetLastError()));
				SleepEx(3000, 0);
				return 0;
			}

			delete[] response;
			ccolor(GREEN, BLACK);
			printf("\r\n > Success!");
			CloseHandle(_hProc);
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
	system("pause");
}