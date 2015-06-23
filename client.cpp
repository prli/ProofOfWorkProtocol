/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2015-06-04
 * 
 * Description:
 * 
 *      This is a sample code to connect to a server through TCP.
 *      You are allowed to use this as a sample / starting point 
 *      for the assignment (both problems require a program that 
 *      connects to something)
 * 
 * Copytight and permissions:
 *      This file is for the exclusive purpose of our ECE-458 
 *      assignment 2, and you are not allowed to use it for any 
 *      other purpose.
 * 
 ********************************************************************/

#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>

#include "encodings.h"
#include "crypto.h"
using namespace cgipp;

int socket_to_server (const char * IP, int port);
string read_packet (int socket);
string processChallenge (string challengeString);
string generate_random_string (int bitSize);

class connection_closed {};
class socket_error {};

int m_port = 34951;

int main()
{
    int socket = socket_to_server ("127.0.0.1", m_port);
        // The function expects an IP address, and not a 
        // hostname such as "localhost" or ecelinux1, etc.
	try{
		if (socket != -1)
		{
			struct timeval tv;

			tv.tv_sec = 30;  /* 30 Secs Timeout */
			tv.tv_usec = 0;  // Not init'ing this can cause strange errors

			//setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
			
			cerr << "CONNECTED" << endl;
			
			string challengeString = read_packet (socket);
			const clock_t receive_timev = clock();

			string responseString = cgipp::hex_encoded(processChallenge(challengeString));
			responseString += '\n';
			
			int count = send (socket, responseString.c_str(), strlen(responseString.c_str()), MSG_NOSIGNAL);
			cerr << responseString << " is " << count << " chars" << endl;
			const clock_t send_timev = clock();
			
			cerr << "processing TIME: " << double( send_timev - receive_timev ) /  CLOCKS_PER_SEC << endl;
			
			
			string result = read_packet (socket);
			cerr << result << endl;
			close (socket);
		}
		else
		{
			cerr << "Failed to connect" << endl;
		}
	}
	catch (connection_closed)
    {
		cerr << "Connection closed" << endl;
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
	
    return 0;
}

int socket_to_server (const char * IP, int port)
{
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr (IP);
    address.sin_port = htons(port);

    int sock = socket (AF_INET, SOCK_STREAM, 0);

    if (connect (sock, (struct sockaddr *) &address, sizeof(address)) == -1)
    {
		cerr << "Error " << errno << endl;
        return -1;
    }

    return sock;
}

string read_packet (int client_socket)
{
    string msg;

    const int size = 8192;
    char buffer[size];

    while (true)
    {
        int bytes_read = recv (client_socket, buffer, sizeof(buffer) - 2, 0);
            // Though extremely unlikely in our setting --- connection from 
            // localhost, transmitting a small packet at a time --- this code 
            // takes care of fragmentation  (one packet arriving could have 
            // just one fragment of the transmitted message)

		if (bytes_read > 0)
        {
            buffer[bytes_read] = '\0';
            buffer[bytes_read + 1] = '\0';

            const char * packet = buffer;
            while (*packet != '\0')
            {
                msg += packet;
                packet += strlen(packet) + 1;
				
                if (msg.length() > 1 && msg[msg.length() - 1] == '\n')
                {
                    // istringstream buf(msg);
                    // string msg_token;
                    // buf >> msg_token;
                    return msg;  // msg_token;
                }
            }
        }

        else if (bytes_read == 0)
        {
            close (client_socket);
            throw connection_closed();
        }

        else
        {
            cerr << "Error " << errno << endl;
            throw socket_error();
        }
    }

    throw connection_closed();
}

string processChallenge (string challengeString)
{
	cerr << "Processing challenge..." << endl;
		
	istringstream iss(challengeString);
	string R_hex;
	getline( iss, R_hex, ' ' );
	string R = cgipp::hex_decoded(R_hex);
	string P;
	getline( iss, P, ' ' );
	P.erase(std::remove(P.begin(), P.end(), '\n'), P.end());
	
	cerr << "P: " << P << "..." << endl;
	string x = generate_random_string(128);
	string hashVal = cgipp::sha256(R + x + R);

	while (hashVal.find(P) != 0)
	{
		//cerr << "hash: " << hashVal << " ..." << endl;
		x = generate_random_string(128);
		hashVal = cgipp::sha256(R + x + R);
	}
	cerr << "hash: " << hashVal << " ..." << endl;
	cerr << "length: " << string(R + x + R).length() << "..." << endl;
	return R + x + R;
}

string generate_random_string (int size)
{
	int charCount = size/8;
	char randomString[charCount];
	FILE *fp = fopen("/dev/urandom", "r");
	int count = fread(&randomString, 1, charCount, fp);
	fclose(fp);
	return string(randomString, charCount);
}
