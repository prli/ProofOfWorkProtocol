/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2015-06-04
 * 
 * Description:
 * 
 *      This is the file used for question 2 of assignment 1.  You
 *      may also use it as sample / starting point to create the 
 *      server for question 1.  In particular, you are allowed to 
 *      submit your code containing verbatim fragments from this 
 *      file.
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

class connection_closed {};
class socket_error {};

void listen_connections (int port);
void process_connection (int client_socket);

string send_challenge (int client_socket);
void verify_reponse (int client_socket, string challengeString, string responseString);

string generate_random_string (int bitSize);
int setTimeout (int matchLength);

string read_packet (int client_socket);

int m_port = 34951;
int p_length;

int main (int na, char * arg[])
{
	if(na != 2)
	{
		cerr << "missing arg for p length, ex) ./server.out 16" << endl;
		return 0;
	}
	istringstream temp(arg[1]);
	if (!(temp >> p_length))
	{
		cerr << "Invalid number -" << arg[1] << endl;
		return 0;
	}
	if(p_length%8 != 0)
	{
		cerr << "must be multiple of 8 -" << arg[1] << endl;
		return 0;
	}
	
    listen_connections (m_port);
    return 0;
}

void listen_connections (int port)
{
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_len;

    server_socket = socket (AF_INET, SOCK_STREAM, 0);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons (port);

    bind (server_socket, (struct sockaddr *) &server_address, sizeof(server_address));

    listen (server_socket, 5);

    while (true)
    {
        client_len = sizeof(client_address);
        client_socket = accept (server_socket,
                                (struct sockaddr *) &client_address,
                                &client_len);

        pid_t pid = fork();
        if (pid == 0)           // if we're the child process
        {
            close (server_socket);    // only the parent listens for new connections

            if (fork() == 0)    // detach grandchild process -- parent returns immediately
            {
                usleep (10000); // Allow the parent to finish, so that the grandparent
                                // can continue listening for connections ASAP

                process_connection (client_socket);
            }

            return;
        }

        else if (pid > 0)       // parent process; close the socket and continue
        {
            int status = 0;
            waitpid (pid, &status, 0);
            close (client_socket);
        }

        else
        {
            cerr << "ERROR on fork()" << endl;
            return;
        }
    }
}

void process_connection (int client_socket)
{
	cerr << "CONNECTED" << endl;
    try
    {
		struct timeval tv;

		tv.tv_sec = setTimeout(p_length);  /* n= 30 is 30 Secs Timeout */
		tv.tv_usec = 0;  // Not init'ing this can cause strange errors

		setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

		string challengeString = send_challenge(client_socket);
		const clock_t send_timev = clock();
		
		cerr << "waiting..." << endl;
		string responseString = read_packet (client_socket);
		const clock_t receive_timev = clock();
		
		cerr << "processing TIME: " << double( receive_timev - send_timev ) /  CLOCKS_PER_SEC << endl;
		if(double( receive_timev - send_timev ) /  CLOCKS_PER_SEC < 0.075)
		{
			cerr << "responded too fast..." << endl;
			close(client_socket);
		}
		
		verify_reponse(client_socket, challengeString, responseString);
        close(client_socket);
    }
    catch (connection_closed)
    {
		cerr << "Connection closed" << endl;
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
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

int setTimeout (int matchLength)
{
	return 30;
}

string send_challenge (int client_socket)
{
	cerr << "sending challenge..." << endl;
	string R = cgipp::hex_encoded(generate_random_string(128));
	string P = cgipp::hex_encoded(generate_random_string(p_length));
	string stringToSend = R + " " + P + '\n';
	int count = send (client_socket, stringToSend.c_str(), strlen(stringToSend.c_str()), MSG_NOSIGNAL);
	return stringToSend;
}

void verify_reponse (int client_socket, string challengeString, string responseString)
{
	istringstream iss(challengeString);
	string R;
	getline( iss, R, ' ' );
	string P;
	getline( iss, P, ' ' );
	P.erase(std::remove(P.begin(), P.end(), '\n'), P.end());
	
	cerr << "verifying response..." << endl;
	//length is 768 bits (hexcoded)
	if (responseString.length() != 96)
	{
		close (client_socket);
		cerr << "response size is too short..." << responseString.length() << endl;
		throw connection_closed();
	}
	
	//starts with R
	if (responseString.find(R) != 0)
	{
		close (client_socket);
		cerr << "does not start with R..." << endl;
		throw connection_closed();
	}
	
	//ends with R
	if (responseString.length() < R.length()
		&& responseString.compare (responseString.length() - R.length(), R.length(), R) != 0) 
	{
		close (client_socket);
		cerr << "does not end with R..." << endl;
		throw connection_closed();
    }
	
	if (cgipp::sha256(cgipp::hex_decoded(responseString)).find(P) != 0)
	{
		close (client_socket);
		cerr << "hashed values does not start with P..." << endl;
		throw connection_closed();
	}
	
	send (client_socket, "ok!\n", 4, MSG_NOSIGNAL);
	cerr << "ok!" << endl;
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
                    istringstream buf(msg);
                    string msg_token;
                    buf >> msg_token;
                    return msg_token;
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
