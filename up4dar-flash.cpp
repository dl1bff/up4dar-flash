/*

Copyright (C) 2012   Michael Dirska, DL1BFF (dl1bff@mdx.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/



#include "stdafx.h"


#define SOFTWARE_IMAGE_PHY			1
#define SOFTWARE_IMAGE_UPDATER		2
#define SOFTWARE_IMAGE_SYSTEM		3
#define SOFTWARE_IMAGE_FLASH_TOOL	4

#define SOFTWARE_MATURITY_NORMAL		0x00
#define SOFTWARE_MATURITY_BETA			0x80
#define SOFTWARE_MATURITY_EXPERIMENTAL	0x40


#define SWVER_BYTE0		(SOFTWARE_IMAGE_FLASH_TOOL | SOFTWARE_MATURITY_NORMAL)
// #define SWVER_BYTE0		(SOFTWARE_IMAGE_FLASH_TOOL | SOFTWARE_MATURITY_EXPERIMENTAL)
#define SWVER_BYTE1		1
#define SWVER_BYTE2		0
#define SWVER_BYTE3		4

unsigned char sw_version[4] = { SWVER_BYTE0, SWVER_BYTE1, SWVER_BYTE2, SWVER_BYTE3 };



void usage( _TCHAR* name )
{
	wprintf(_T("\nUsage: %s <COMPORT> <FirmwareFile> [/DEBUG]\n"), name);

	wprintf(_T("\nThe following COM ports are active on this system:\n") );

	int comport_count = 0;

	for (int i=1; i<256; i++)
	{
    
		WCHAR buf[20];

		wsprintf(buf, _T("COM%d"), i);

		COMMCONFIG cc;
		DWORD dwSize = sizeof(COMMCONFIG);
		if (GetDefaultCommConfig(buf, &cc, &dwSize))
		{
			wprintf(_T("   %s\n"), buf);
			comport_count++;
		}
	}

	if (comport_count == 0)
	{
		wprintf(_T("   NONE - no COM ports found\n") );
	}

	exit(1);
}

#define FLASH_BLOCK_SIZE	512

unsigned char fw_buf[1000 * FLASH_BLOCK_SIZE];
int fw_buf_len;
int fw_send_counter;

HANDLE hSerial;

int debug_flag = 0;


static int hex_value(int ch)
{
	if ((ch >= '0') && (ch <= '9'))
	{
		return ch - 48;
	}
	else if ((ch >= 'A') && (ch <= 'F'))
	{
		return (ch - 65) + 10;
	}
	else if ((ch >= 'a') && (ch <= 'f'))
	{
		return (ch - 97) + 10;
	}

	return -1;
}

static int checksum_is_correct(void)
{
	SHA1Context ctx;

	int image_len = fw_buf_len - FLASH_BLOCK_SIZE;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, fw_buf, image_len);
	SHA1Result(&ctx);

	int i;
	unsigned char sha1_buf_1[20];
	

	for (i=0; i < 5; i++)
	{
		unsigned int d = ctx.Message_Digest[i];

		/*
		printf ("%02x ", ((d >> 24) & 0xFF) );
		printf ("%02x ", ((d >> 16) & 0xFF) );
		printf ("%02x ", ((d >>  8) & 0xFF) );
		printf ("%02x ", ((d      ) & 0xFF) );
		*/

		sha1_buf_1[i*4 + 0] = ((d >> 24) & 0xFF);
		sha1_buf_1[i*4 + 1] = ((d >> 16) & 0xFF);
		sha1_buf_1[i*4 + 2] = ((d >>  8) & 0xFF);
		sha1_buf_1[i*4 + 3] = ((d      ) & 0xFF);
	}

	// printf ("\n");

	unsigned char sha1_buf_2[20];
	int count = 0;
	int nibble = 0;

	for (i=0; i < 80; i++)
	{
		int v = hex_value( fw_buf[image_len + i]);

		if (v >= 0)
		{
			if (nibble == 0)
			{
				sha1_buf_2[count] = v << 4;
				nibble = 1;
			}
			else
			{
				sha1_buf_2[count] |= v;
				nibble = 0;
				count ++;

				if (count >= 20)
				  break;
			}
		}
	}

	// printf ("\n");

	if (count == 20)
	{
		return ( memcmp(sha1_buf_1, sha1_buf_2, 20) == 0);
	}

	return 0;
}

static void version2string (_TCHAR * buf, const unsigned char * version_info)
{
		_TCHAR image = _T('?');
		_TCHAR maturity = 0;
		
		switch(version_info[0] & 0x0F)
		{
			case 1:
			image = _T('P'); // PHY image
			break;
			case 2:
			image = _T('U'); // Updater image
			break;
			case 3:
			image = _T('S'); // System image
			break;
			case 4:
			image = _T('F'); // System image
			break;
		}
		
		switch(version_info[0] & 0xC0)
		{
			case 0x80:
			maturity = _T('b');
			break;
			case 0x40:
			maturity = _T('e');
			break;
		}
		
		buf[0] = image;
		buf[1] = _T('.');
		wsprintf(buf + 2, _T("%1d"), version_info[1]);
		buf[3] = _T('.');
		wsprintf(buf + 4, _T("%02d"), version_info[2]);
		buf[6] = _T('.');
		wsprintf(buf + 7, _T("%02d"), version_info[3]);
		buf[9] = maturity;
		buf[10] = 0;
}


static unsigned char byte_buf[1200];
static int byte_buf_ptr = 0;

static void send_byte_flush (void)
{
	DWORD dwBytes;

	dwBytes = byte_buf_ptr;

	if(!WriteFile(hSerial, byte_buf, byte_buf_ptr, &dwBytes, NULL))
	{
		wprintf(_T("\nERROR: WriteFile failed\n") );
		exit(2);
	}

	if (dwBytes != byte_buf_ptr)
	{
		wprintf(_T("\nERROR: WriteFile short write\n") );
		exit(2);
	}

	byte_buf_ptr = 0;
}

static void send_byte (int d)
{
	if (d == 0x10)
	{
		byte_buf[byte_buf_ptr] = d;
		byte_buf_ptr ++;
	}

	byte_buf[byte_buf_ptr] = d;
	byte_buf_ptr ++;

	if (byte_buf_ptr >= ((sizeof byte_buf) - 2))
	{
		wprintf(_T("\nERROR: send_byte overflow\n") );
		exit(2);
	}
}


static void print_debug ( const _TCHAR * prefix, int cmd, int len,
						unsigned char * d )
{
	if (debug_flag != 0)
	{
		int i;

		wprintf(_T("%s: %02x"), prefix, cmd);

#define MAX_OUTPUT_DEBUG_BYTES 8

		for (i=0; (i < len) && (i < MAX_OUTPUT_DEBUG_BYTES); i++)
		{
			wprintf(_T(" %02x"), d[i]);
		}

		if (len > MAX_OUTPUT_DEBUG_BYTES)
		{
			wprintf(_T(" ..."));
		}

		wprintf(_T("\n"));
	}
}


static void send_cmd (int cmd, int len, unsigned char * d)
{
	unsigned char buf[2];
	DWORD dwBytes;
	int i;

	print_debug(_T("TX"), cmd, len, d);

	buf[0] = 0x10;
	buf[1] = 0x02; // STX
	
	dwBytes = 2;
	if(!WriteFile(hSerial, buf, dwBytes, &dwBytes, NULL))
	{
		wprintf(_T("\nERROR: WriteFile failed\n") );
		exit(2);
	}

	if (dwBytes != 2)
	{
		wprintf(_T("\nERROR: WriteFile short write\n") );
		exit(2);
	}

	send_byte(cmd);

	for (i=0; i < len; i++)
	{
		send_byte(d[i]);
	}

	send_byte_flush();

	buf[0] = 0x10;
	buf[1] = 0x03; // ETX
	
	dwBytes = 2;
	if(!WriteFile(hSerial, buf, dwBytes, &dwBytes, NULL))
	{
		wprintf(_T("\nERROR: WriteFile failed\n") );
		exit(2);
	}

	if (dwBytes != 2)
	{
		wprintf(_T("\nERROR: WriteFile short write\n") );
		exit(2);
	}
}

static void send_cmd_with_arg1(int cmd, int arg1)
{
	unsigned char c;

	c = arg1;

	send_cmd(cmd, 1, &c);
}

static void send_cmd_without_arg(int cmd)
{
	send_cmd(cmd, 0, 0);
}

#define PHY_VERSION_STRING_LEN 54

static int parse_version_string (const char * s, const char * prefix,
				unsigned char * version_numbers, int num_numbers )
{
	int i;
	if (num_numbers >= 5)
	{
		return 0;
	}

	unsigned char numbers_seen[4];

	for (i=0; i < num_numbers; i++)
	{
		version_numbers[i] = 0;
		numbers_seen[i] = 0;
	}

	int number_ptr = 0;

	const char * ptr = strstr(s, prefix);

	if (ptr != NULL)
	{
		ptr += strlen(prefix); // go to start of numbers
		
		while (1)
		{
			switch (*ptr)
			{
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				numbers_seen[number_ptr] = 1;
				version_numbers[number_ptr] =
					version_numbers[number_ptr] * 10 + ((*ptr) & 0x0F);
				break;
			case '.':
				if (numbers_seen[number_ptr] == 0)
				{
					return 0; // no numbers before dot
				}
				number_ptr ++;
				if (number_ptr >= num_numbers)
				{
					return 0;  // too many dots
				}
				break;
			default:
				if (numbers_seen[number_ptr] == 0)
				{
					return 0; // no numbers after last dot
				}
				if ((number_ptr + 1) == num_numbers)
				{
					return 1; // right number of dots
				}
				return 0;
			}
			ptr ++;
		}
	}

	return 0;
}




static int recv_state = 0;
static int switch_rs232_to_phy = 0;


static int recv_packet( unsigned char * p, int len )
{
	int i;
	_TCHAR cbuf[20];

	print_debug(_T("RX"), p[0], len-1, p+1);

	switch (p[0])
	{
	case 0x01:
	
		if (len >= 70)
		{
			char vbuf[PHY_VERSION_STRING_LEN + 1];

			printf("  ");

			for (i=1; i < PHY_VERSION_STRING_LEN + 1; i++)
			{
				if (p[i] >= 32)
				{
					printf ("%c", p[i]);
				}
				else
				{
					printf (".");
				}
				vbuf[i-1] = p[i];
			}
			vbuf[PHY_VERSION_STRING_LEN] = 0;

			printf ("\n  S/N: ");
			char hyphen = ' ';
			for (i=PHY_VERSION_STRING_LEN + 1; i < 70; i++)
			{	
				printf ("%c%02x", hyphen, p[i]);
				hyphen = '-';
			}
			printf ("\n");

			unsigned char u_ver_buf[4];
			u_ver_buf[0] = SOFTWARE_IMAGE_UPDATER;

			unsigned char p_ver_buf[4];
			p_ver_buf[0] = SOFTWARE_IMAGE_PHY;

			int phy_version_seen =
				parse_version_string(vbuf, "SW-Ver: ", p_ver_buf+1, 3);

			int updater_version_seen =
				parse_version_string(vbuf, "UP4DAR Updater U.", u_ver_buf+1, 3);

			if (recv_state == 0)
			{
				if (updater_version_seen)
				{
					version2string(cbuf, u_ver_buf);

					wprintf(_T("Updater Firmware version on UP4DAR: %s\n"), cbuf);
					
					if (switch_rs232_to_phy)
					{
						send_cmd_without_arg(0xEF); // switch to PHY
						send_cmd_without_arg(0x01); // get info from PHY
					}
					else
					{
						send_cmd_without_arg(0xE1); // switch to flash mode
						recv_state = 2;
					}
				}
				else if (phy_version_seen) // real software running
				{
					version2string(cbuf, p_ver_buf);

					wprintf(_T("PHY Firmware version on UP4DAR: %s\n"), cbuf);

					send_cmd_with_arg1(0xD3, 0x01); // switch to service mode
					recv_state = 1;
				}
				else 
				{
					send_cmd_without_arg(0xE1); // switch to flash mode
					recv_state = 2;
				}
			}
			else if (recv_state == 4)
			{
				if (updater_version_seen && !switch_rs232_to_phy)
				{
					wprintf(_T("\nSystem Firmware upload done.\n"));
					exit(0);
				}
				if (phy_version_seen) // new software running
				{
					version2string(cbuf, p_ver_buf);

					wprintf(_T("\nPHY Firmware version on UP4DAR now: %s\n"), cbuf);

					exit(0);
				}
			}
		}
		else // len == 70
		{
			wprintf (_T("Info: len %d\n"), len);
		}
		break;

	case 0xD4: // cmd exec
		if (len >= 2)
		{
			if ((recv_state == 1) && (p[1] == 2)) // switch to service mode failed:
										// UP4DAR already in service mode
			{
				send_cmd_without_arg(0xE1); // switch to flash mode
				recv_state = 2;
				break;
			}
			
			if (p[1] != 1) // unexpected result
			{
				wprintf (_T("cmd result=%d\n"), p[1]);
				wprintf (_T("\nERROR\n"));
				exit(3);
			}

			if (recv_state == 3)
			{
				fw_send_counter ++;

				if (fw_send_counter >= (fw_buf_len / FLASH_BLOCK_SIZE))
				{
					send_cmd_without_arg (0xE3);  // end of flash
					recv_state = 4;  // wait for version_info
				}
				else
				{
					wprintf(_T("sending block %3d of %3d\r"),
						fw_send_counter+1, (fw_buf_len / FLASH_BLOCK_SIZE));
					if (debug_flag != 0)
					{
						wprintf(_T("\n"));
					}
					send_cmd( 0xE2, FLASH_BLOCK_SIZE, fw_buf +
						(fw_send_counter * FLASH_BLOCK_SIZE));
				}
			}
		}
		break;

	case 0xD1: // mode info
		if (len >= 3)
		{	
			if ((p[1] != 1) && (p[2] != 0)) // unexpected result
			{
				wprintf (_T("mode=%d  state=%d\n"), p[1], p[2]);
				wprintf (_T("\nERROR\n"));
				exit(3);
			}

			if (recv_state == 1)
			{
				send_cmd_without_arg(0xE1); // switch to flash mode
				recv_state = 2;
			}
		}
		break;

	case 0xE4: // update mode
		wprintf (_T("UP4DAR is now in update mode\n"));
		if (recv_state == 2)
		{
			recv_state = 3;
			wprintf(_T("sending block   1 of %3d\r"),
						(fw_buf_len / FLASH_BLOCK_SIZE));
			if (debug_flag != 0)
			{
				wprintf(_T("\n"));
			}
			send_cmd( 0xE2, FLASH_BLOCK_SIZE, fw_buf);
			fw_send_counter = 0;
		}
		break;

	default:
		wprintf (_T("unknown 0x%02x len %d\n"), p[0], len);
		
		break;
	}



	return 0;
}


static void main_loop (void)
{
	int timeout = 30;

	int escape = 0;

#define PACKET_MAX_SIZE 120
	unsigned char packet_buf[PACKET_MAX_SIZE];
	int packet_buf_ptr = -1;

	while(1)
	{
		unsigned char d;
		DWORD dwBytes = 0;
		if(!ReadFile(hSerial, &d, 1, &dwBytes, NULL))
		{
			wprintf(_T("\nERROR: ReadFile on COM port failed\n") );
			exit(2);
		}

		if (dwBytes == 1)
		{
			timeout = 30;

			if (escape != 0)
			{
				switch (d)
				{
				case 0x10: // DLE
					if (packet_buf_ptr >= 0)
					{
						packet_buf[packet_buf_ptr] = d;
						packet_buf_ptr ++;
					}
					break;
				case 0x02: // STX
					packet_buf_ptr = 0;
					break;
				case 0x03: // ETX
					if (recv_packet(packet_buf, packet_buf_ptr) != 0)
						return;
					break;

				default:
					packet_buf_ptr = -1;
					break;
				}

				escape = 0;
			}
			else 
			{
				if (d == 0x10) // DLE
				{
					escape = 1;
				}
				else if (packet_buf_ptr >= 0)
				{
					packet_buf[packet_buf_ptr] = d;
					packet_buf_ptr ++;
				}
			}

			if (packet_buf_ptr >= PACKET_MAX_SIZE) // overflow
			{
				packet_buf_ptr = -1;
			}
		}
		else
		{
			timeout --;
			if (timeout <= 0)
				return;
		}
	}
}






int _tmain(int argc, _TCHAR* argv[])
{
	_TCHAR cbuf[20];

	if (argc < 3)
	{
		usage(argv[0]);
	}

	if (argc > 3)
	{
		if (wcscmp( argv[3], _T("/DEBUG")) == 0)
		{
			debug_flag = 1;
		}
	}

	version2string(cbuf, sw_version);

	wprintf(_T("\nUP4DAR Flash Tool Version: %s\n"), cbuf );
	wprintf(_T(" (C) 2012 Michael Dirska, DL1BFF\n\n"));
	
	
	hSerial = CreateFile(argv[1],  // COM port
			GENERIC_READ | GENERIC_WRITE,
			0,
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			0);
	if(hSerial==INVALID_HANDLE_VALUE)
	{
		if(GetLastError()==ERROR_FILE_NOT_FOUND)
		{
		
			wprintf(_T("\nERROR: COM port %s not found\n"), argv[1] );
			usage(argv[0]);
		}
	
		wprintf(_T("\nERROR: could not open COM port %s\n"), argv[1] );
		usage(argv[0]);
	}

	DCB dcbSerialParams = {0};
	dcbSerialParams.DCBlength=sizeof(dcbSerialParams);
	if (!GetCommState(hSerial, &dcbSerialParams))
	{
		wprintf(_T("\nERROR: GetCommState on %s failed\n"), argv[1] );
		usage(argv[0]);
	}
	dcbSerialParams.BaudRate=CBR_115200;
	dcbSerialParams.ByteSize=8;
	dcbSerialParams.StopBits=ONESTOPBIT;
	dcbSerialParams.Parity=NOPARITY;
	if(!SetCommState(hSerial, &dcbSerialParams))
	{
		wprintf(_T("\nERROR: SetCommState on %s failed\n"), argv[1] );
		usage(argv[0]);
	}

	COMMTIMEOUTS timeouts={0};
	timeouts.ReadIntervalTimeout= 10000;
	timeouts.ReadTotalTimeoutConstant=100;
	timeouts.ReadTotalTimeoutMultiplier=0;

	timeouts.WriteTotalTimeoutConstant=50;
	timeouts.WriteTotalTimeoutMultiplier=1;

	if(!SetCommTimeouts(hSerial, &timeouts))
	{
		wprintf(_T("\nERROR: SetCommTimeouts on %s failed\n"), argv[1] );
		usage(argv[0]);
	}

	char ch = 'A';
	DWORD dwBytes = 1;
	if(!WriteFile(hSerial, &ch, 1, &dwBytes, NULL))
	{
		wprintf(_T("\nERROR: WriteFile on %s failed\n"), argv[1] );
		usage(argv[0]);
	}

	if (dwBytes != 1)
	{
		wprintf(_T("\nERROR: WriteFile on %s short write\n"), argv[1] );
		usage(argv[0]);
	}


	HANDLE hFile;
	hFile = CreateFile(argv[2],  // Firmware file
			GENERIC_READ,
			0,
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			0);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		if(GetLastError()==ERROR_FILE_NOT_FOUND)
		{
		
			wprintf(_T("\nERROR: firmware file %s not found\n"), argv[2] );
			usage(argv[0]);
		}
	
		wprintf(_T("\nERROR: could not firmware file port %s\n"), argv[2] );
		usage(argv[0]);
	}

	
	dwBytes = 0;
	if(!ReadFile(hFile, fw_buf, sizeof fw_buf, &dwBytes, NULL))
	{
		wprintf(_T("\nERROR: ReadFile on %s failed\n"), argv[2] );
		usage(argv[0]);
	}

	if (dwBytes == 0)
	{
		wprintf(_T("\nERROR: firmware file %s is empty\n"), argv[2] );
		usage(argv[0]);
	}

	if ((dwBytes % FLASH_BLOCK_SIZE) != 0)
	{
		wprintf(_T("\nERROR: firmware file %s: file size is not an integer multiple of %d\n"),
			argv[2], FLASH_BLOCK_SIZE );
		usage(argv[0]);
	}

	wprintf(_T("Firmware file: %d bytes\n"), dwBytes);

	fw_buf_len = dwBytes;

	unsigned char sw_version[4];

	if (checksum_is_correct())
	{
		memcpy (sw_version, fw_buf + 4, 4); // copy firmware version info
	}
	else
	{	// possibly PHY image


		char vbuf[PHY_VERSION_STRING_LEN + 1];
		int i;

		for (i=0; i < PHY_VERSION_STRING_LEN; i++)
		{
			vbuf[i] = fw_buf[FLASH_BLOCK_SIZE - 64 + i];
		}
		
		vbuf[PHY_VERSION_STRING_LEN] = 0;

		unsigned char hw_version[2];

		if (parse_version_string(vbuf, "HW-Ver: ", hw_version, 2)
			&& parse_version_string(vbuf, "SW-Ver: ", sw_version + 1, 3))
		{
			if ((hw_version[0] == 1) && (hw_version[1] == 1))
			{
				sw_version[0] = SOFTWARE_IMAGE_PHY;
			}
		}
	}

	version2string(cbuf, sw_version);

	switch(cbuf[0])
	{
	case _T('S'):
		break;
	case _T('U'):
		break;
	case _T('P'):
		switch_rs232_to_phy = 1;
		break;
	default:
		wprintf(_T("\nERROR: Firmware file not recognized\n"));
		return 1;
	}

	wprintf(_T("Firmware version in file: %s\n"), cbuf);

	send_cmd_without_arg( 0x01 ); // info

	main_loop();

	wprintf(_T("\nERROR: UP4DAR does not respond, timeout occured\n"));

	return 1;
}

