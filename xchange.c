// xchange - verify or change idcode and/or CRC of Xilinx FPGA bitstream files
//
// Copyright 2018 Eric Smith <spacewar@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of version 3 of the GNU General Public License
// as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "crc32c_br.h"


const char *progname;
unsigned int debug;

FILE *inf  = NULL;
FILE *outf = NULL;


uint32_t crc;
bool crc_reset;
bool crc_error;

const char *partnum_str = NULL;
const char *idcode_str = NULL;
const char *package_str = NULL;

bool replace_idcode = false;
uint32_t new_idcode;


typedef struct
{
  uint32_t idcode;
  uint32_t idcode_mask;
  uint32_t jtag_ir_length;
  const char *name;
} part_info_t;


const part_info_t part_info[] =
{
  // From UG470
  { 0x03622093, 0x0fffffff,  6, "xc7s6" },
  { 0x03620093, 0x0fffffff,  6, "xc7s15" },
  { 0x037c4093, 0x0fffffff,  6, "xc7s25" },
  { 0x0362f093, 0x0fffffff,  6, "xc7s50" },
  { 0x037c8093, 0x0fffffff,  6, "xc7s75" },
  { 0x037c7093, 0x0fffffff,  6, "xc7s100" },
                               
  { 0x037c3093, 0x0fffffff,  6, "xc7a12t" },
  { 0x0362e093, 0x0fffffff,  6, "xc7a15t" }, // value in UG470 1.10 wrong
  { 0x037c2093, 0x0fffffff,  6, "xc7a25t" },
  { 0x0362d093, 0x0fffffff,  6, "xc7a35t" },
  { 0x0362c093, 0x0fffffff,  6, "xc7a50t" },
  { 0x03632093, 0x0fffffff,  6, "xc7a75t" },
  { 0x03631093, 0x0fffffff,  6, "xc7a100t" },
  { 0x03636093, 0x0fffffff,  6, "xc7a200t" },
                               
  { 0x03647093, 0x0fffffff,  6, "xc7k70t" },
  { 0x0364c093, 0x0fffffff,  6, "xc7k160t" },
  { 0x03651093, 0x0fffffff,  6, "xc7k325t" },
  { 0x03747093, 0x0fffffff,  6, "xc7k355t" },
  { 0x03656093, 0x0fffffff,  6, "xc7k410t" },
  { 0x03752093, 0x0fffffff,  6, "xc7k420t" },
  { 0x03751093, 0x0fffffff,  6, "xc7k480t" },
                               
  { 0x03671093, 0x0fffffff,  6, "xc7v585t" },
                               
// Note that XC7V2000T IDCODE has additional don't care bits 15..14
  { 0x036b3093, 0x0fff3fff, 24, "xc7v2000t" },

  { 0x03667093, 0x0fffffff,  6, "xc7vx330t" },
  { 0x03682093, 0x0fffffff,  6, "xc7vx415t" },
  { 0x03687093, 0x0fffffff,  6, "xc7vx485t" },
  { 0x03692093, 0x0fffffff,  6, "xc7vx550t" },
  { 0x03696093, 0x0fffffff,  6, "xc7vx690t" },
  { 0x036d5093, 0x0fffffff, 24, "xc7vx1140t" },

  { 0x036d9093, 0x0fffffff, 22, "xc7vh580t" },
  { 0x036db093, 0x0fffffff, 38, "xc7vh870t" },

  // There does not appear to be any official source for XC7Z idcode values
  { 0x03723093, 0x0fffffff,  6, "xc7z007" },
  { 0x03722093, 0x0fffffff,  6, "xc7z010" },
  // unknown "ZC7Z012S"
  // unknown "ZC7Z014S"
  { 0x0373b093, 0x0fffffff,  6, "xc7z015" },
  { 0x03727093, 0x0fffffff,  6, "xc7z020" },
  { 0x0372c093, 0x0fffffff,  6, "xc7z030" },
  // unknown "ZC7Z035"
  { 0x03731093, 0x0fffffff,  6, "xc7z045" },
  { 0x03736093, 0x0fffffff,  6, "xc7z100" },

  // from UG570
  { 0x03824093, 0x0fffffff,  6, "xcku025" },
  { 0x03823093, 0x0fffffff,  6, "xcku035" },
  { 0x03822093, 0x0fffffff,  6, "xcku040" },
  { 0x03919093, 0x0fffffff,  6, "xcku060" },
  { 0x0380f093, 0x0fffffff, 12, "xcku085" },
  { 0x03844093, 0x0fffffff,  6, "xcku095" },
  { 0x0390d093, 0x0fffffff, 12, "xcku115" },

  { 0x03939093, 0x0fffffff,  6, "xcvu065" },
  { 0x03843093, 0x0fffffff,  6, "xcvu080" },
  { 0x03842093, 0x0fffffff,  6, "xcvu095" },
  { 0x0392d093, 0x0fffffff, 12, "xcvu125" },
  { 0x03933093, 0x0fffffff, 18, "xcvu160" },
  { 0x03931093, 0x0fffffff, 18, "xcvu190" },
  { 0x0396d093, 0x0fffffff, 18, "xcvu440" },

  { 0x04a63093, 0x0fffffff,  6, "xcku3p" },
  { 0x04a62093, 0x0fffffff,  6, "xcku5p" },
  { 0x0484a093, 0x0fffffff,  6, "xcku9p" },
  { 0x04a4e093, 0x0fffffff,  6, "xcku11p" },
  { 0x04a52093, 0x0fffffff,  6, "xcku13p" },
  { 0x04a56093, 0x0fffffff,  6, "xcku15p" },

  { 0x04b39093, 0x0fffffff,  6, "xcvu3p" },
  { 0x04b2b093, 0x0fffffff, 12, "xcvu5p" },
  { 0x04b29093, 0x0fffffff, 12, "xcvu7p" },
  { 0x04b31093, 0x0fffffff, 12, "xcvu9p" },
  { 0x04b49093, 0x0fffffff, 18, "xcvu11p" },
  { 0x04b51093, 0x0fffffff, 24, "xcvu13p" },
  { 0x04b6b093, 0x0fffffff,  6, "xcvu31p" },
  { 0x04b69093, 0x0fffffff,  6, "xcvu33p" },
  { 0x04b71093, 0x0fffffff, 12, "xcvu35p" },
  { 0x04b79093, 0x0fffffff, 18, "xcvu37p" },

  // from UG1085
  { 0x04711093, 0x0fffffff,  6, "xczu2" },
  { 0x04710093, 0x0fffffff,  6, "xczu3" },
  { 0x04721093, 0x0fffffff,  6, "xczu4" },
  { 0x04720093, 0x0fffffff,  6, "xczu5" },
  { 0x04739093, 0x0fffffff,  6, "xczu6" },
  { 0x04730093, 0x0fffffff,  6, "xczu7" },
  { 0x04738093, 0x0fffffff,  6, "xczu9" },
  { 0x04740093, 0x0fffffff,  6, "xczu11" },
  { 0x04750093, 0x0fffffff,  6, "xczu15" },
  { 0x04759093, 0x0fffffff,  6, "xczu17" },
  { 0x04758093, 0x0fffffff,  6, "xczu19" },
  { 0x047e1093, 0x0fffffff,  6, "xczu21" },
  { 0x047e5093, 0x0fffffff,  6, "xczu25" },
  { 0x047e4093, 0x0fffffff,  6, "xczu27" },
  { 0x047e0093, 0x0fffffff,  6, "xczu28" },
  { 0x047e2093, 0x0fffffff,  6, "xczu29" },
};


#define MAX_PART_INFO (sizeof(part_info)/sizeof(part_info_t))


const char *cmd_name[32] =
{
  [0x00] = "null",
  [0x01] = "wcfg",
  [0x02] = "mfw",
  [0x03] = "dghigh/lfrm",
  [0x04] = "rcfg",
  [0x05] = "start",
  [0x06] = "rcap",
  [0x07] = "rcrc",
  [0x08] = "aghigh",
  [0x09] = "switch",
  [0x0a] = "grestore",
  [0x0b] = "shutdown",
  [0x0c] = "gcapture",
  [0x0d] = "desync",
  [0x0e] = "reserved-0x0e",
  [0x0f] = "iprog",
  [0x10] = "crcc",
  [0x11] = "ltimer",
  [0x12] = "bspi_read",
  [0x13] = "fall_edge"
};


typedef struct
{
  const char *name;
  bool skip_crc;
} reg_info_t;

const reg_info_t reg_info[32] =
{
  [0x00] = { "crc",         true },
  [0x01] = { "far",         false },
  [0x02] = { "fdri",        false },
  [0x03] = { "fdro",        false }, // not in SIM_CONFIGURE2.vhd?
  [0x04] = { "cmd",         false },
  [0x05] = { "ctl0",        false },
  [0x06] = { "mask",        false },
  [0x07] = { "stat",        false }, // ?
  [0x08] = { "lout",        false },
  [0x09] = { "cor0",        false },
  [0x0a] = { "mfwr",        false },
  [0x0b] = { "cbc",         false },
  [0x0c] = { "idcode",      false },
  [0x0d] = { "axss",        false },
  [0x0e] = { "cor1",        false },
  [0x10] = { "wbstar",      false },
  [0x11] = { "timer",       false },
  [0x16] = { "bootsts",     true },
  [0x18] = { "ctl1",        false },
  [0x1f] = { "bspi",        false },

  // The following registers are not documented in UG470, but are found
  // in unisims SIM_CONFIGE2.vhd.
  [0x0f] = { "csob",        true },
  [0x13] = { "rbcrc",       false },
  [0x17] = { "testmode",    false },
  [0x19] = { "memrd_param", false },
  [0x1a] = { "dwc",         false },
  [0x1b] = { "trim",        false },
  [0x1e] = { "bout",        false },

  // The following registers are not in UG470 or unisims, but are skipped
  // when performing CRC computation in unisims.
  [0x12] = { "unk12",       true },
  [0x14] = { "unk14",       true },
  [0x15] = { "unk15",       true },

  // 0x1c and 0x1d aren't mentioned in unisims at all.
};



void usage(FILE *f)
{
  fprintf(f, "Usage: %s [options] bitfile\n", progname);
  fprintf(f, "options:\n");
  fprintf(f, "  -p <partnum>\n");
  fprintf(f, "  -i <idcode>\n");
  fprintf(f, "  -k <package>\n");
  fprintf(f, "  -o <outfile>\n");
}


/* generate fatal error message to stderr, doesn't return */
noreturn void fatal(int ret, char *format, ...)
{
  va_list ap;

  fprintf(stderr, "fatal error: ");
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  if (ret == 1)
    usage(stderr);
  exit(ret);
}


size_t get_offset(void)
{
  return ftell(inf);
}


static void write_bytes(size_t count, uint8_t *buffer)
{
  if (! outf)
    return;
  if (fwrite(buffer, 1, count, outf) != count)
    fatal(2, "write error");
}

static void read_bytes(size_t count, uint8_t *buffer)
{
  if (fread(buffer, 1, count, inf) != count)
    fatal(2, "read error");
}

static void rw_bytes(size_t count, uint8_t *buffer)
{
  read_bytes(count, buffer);
  write_bytes(count, buffer);
}

static void copy_bytes(size_t count)
{
  if (outf)
    {
      uint8_t buffer[64];

      while (count)
	{
	  size_t c2;

	  c2 = count;
	  if (c2 > sizeof(buffer))
	    c2 = sizeof(buffer);
	  rw_bytes(c2, buffer);
	  count -= c2;
	}
    }
  else
    {
      if (fseek(inf, count, SEEK_CUR) < 0)
	fatal(2, "input seek error");
    }
}

uint32_t read_uint(size_t count)
{
  uint32_t v = 0;

  while (count--)
    {
      uint8_t b;
      read_bytes(1, & b);
      v = (v << 8) | b;
    }
  return v;
}


void write_uint(size_t count, uint32_t data)
{
  uint8_t buffer[4];
  if (! outf)
    return;
  for (int i = count - 1; i >= 0; i--)
    {
      buffer[i] = data & 0xff;
      data >>= 8;
    }
  if (fwrite(buffer, 1, count, outf) != count)
    fatal(2, "write error");
}


uint32_t rw_uint(size_t count)
{
  uint32_t data;

  data = read_uint(count);
  write_uint(count, data);
  return data;
}


const part_info_t *find_part_by_idcode(uint32_t idcode)
{
  for (unsigned int i = 0; i < MAX_PART_INFO; i++)
  {
    const part_info_t *pi = & part_info[i];
    if ((idcode & pi->idcode_mask) == pi->idcode)
      return pi;
  }
  return NULL;
}

const part_info_t *find_part_by_part_number(const char *part_number)
{
  for (unsigned int i = 0; i < MAX_PART_INFO; i++)
  {
    const part_info_t *pi = & part_info[i];
    if (strcmp(part_number, pi->name) == 0)
      return pi;
  }
  return NULL;
}


#define MAX_B_HEADER_LEN 100
static void munge_b_header(uint32_t len)
{
  char buf[MAX_B_HEADER_LEN+2];

  char base_part_num[MAX_B_HEADER_LEN+2];
  char package_name[MAX_B_HEADER_LEN+2];

  const part_info_t *best_pi = NULL;

  base_part_num[0] = '\0';
  package_name[0] = '\0';

  if (len > sizeof(buf))
    fatal(2, "b header (device name) too long");
  read_bytes(len, (uint8_t *) buf);
  printf("original b header: \"%s\"\n", buf);
  
  if (isdigit(buf[0]))
    {
      if (debug)
	printf("prefacing with \"xc\"\n");
      memmove(& buf[2], & buf[0], strlen(buf)+1);
      buf[0] = 'x';
      buf[1] = 'c';
    }

  for (unsigned int i = 0; i < MAX_PART_INFO; i++)
    {
      const part_info_t *pi = & part_info[i];
      if (strncmp(buf, pi->name, strlen(pi->name)) != 0)
	continue;
      best_pi = pi;
      // a later part may match better, so continue looping
    }

  if (best_pi)
    {
      if (debug)
	printf("matched %s\n", best_pi->name);
      size_t bpn_len = strlen(best_pi->name);
      strncpy(base_part_num, buf, bpn_len);
      if (debug)
	printf("base pn: %s\n", base_part_num);
      strcpy(package_name, buf + bpn_len);
      if (debug)
	printf("package: %s\n", package_name);
    }

  if (partnum_str)
    {
      strcpy(base_part_num, partnum_str);
      if (debug)
	printf("replaced pn with %s\n", base_part_num);
    }

  if (package_str)
    {
      strcpy(package_name, package_str);
      if (debug)
	printf("replaced package with %s\n", package_str);
    }

  if (! base_part_num[0])
    fatal(3, "must specify part number");

  if (! package_name[0])
    fatal(3, "must specify package");

  if (strncmp(base_part_num, "xc", 2) == 0)
    {
      if (debug)
	printf("removing \"xc\"\n");
      memmove(& base_part_num[0], & base_part_num[2], strlen(base_part_num+2)+1);
    }
    
  int n = snprintf(buf, sizeof(buf), "%s%s", base_part_num, package_name);
  printf("replacing b header with \"%s\"\n", buf);
  write_bytes(n+1, (uint8_t *) buf);
}


/*
 * process BIT file header, which is NOT sent to the FPGA
 * format not documented by Xilinx
 *   http://www.fpga-faq.com/FAQ_Pages/0026_Tell_me_about_bit_files.htm
 *   http://security.cs.rpi.edu/courses/hwre-spring2014/Lecture19_FPGA.pdf
 */
static void read_bit_header(uint32_t *config_len)
{
  while (true)
    {
      uint32_t key;
      size_t len_len;
      uint32_t len;

      key = rw_uint(1);
      switch (key)
	{
	case 0x00: len_len = 1; break;
	case 0x62: len_len = 2; break;
	case 0x63: len_len = 2; break;
	case 0x64: len_len = 2; break;
	case 0x65: len_len = 4; break;
	default:
	  fatal(2, "unknown bit header field key %02x", key);
	}
      len = rw_uint(len_len);
      if (key == 0x65)
	{
	  *config_len = len;
	  return;
	}
      if (replace_idcode && (key == 0x62))
	munge_b_header(len);
      else
	copy_bytes(len);
    }
}


void read_sync_word(void)
{
  while (true)
    {
      uint32_t word = rw_uint(4);
      if (word == 0xffffffff)
	continue;  // dummy pad word
      if (word == 0x000000bb)
	{
	  word = rw_uint(4);
	  if (word != 0x11220044)
	    fatal(2, "invalid bus width autodetect word 2 0x%08x", word);
	  continue;
	}
      if (word == 0xaa995566)
	return;
      fatal(2, "unexpected word 0x%08x in bitstream before sync word", word);
    }
}


void update_crc(uint32_t register_address, uint32_t data_word)
{
  if (crc_reset)
    {
      if (debug)
	printf("initializing crc\n");
      crc = 0;
      crc_reset = false;
      return;
    }

  if (reg_info[register_address].skip_crc)
    return;

  crc = crc32c_br_8(crc, (data_word >>  0) & 0xff);
  crc = crc32c_br_8(crc, (data_word >>  8) & 0xff);
  crc = crc32c_br_8(crc, (data_word >> 16) & 0xff);
  crc = crc32c_br_8(crc, (data_word >> 24) & 0xff);
  crc = crc32c_br_5(crc, register_address);
}


uint32_t register_address;
uint32_t opcode;
uint32_t buffered_data;


void reg_write_crc(uint32_t data_word)
{
  if (data_word == crc)
    {
      if (debug)
	printf("crc: file 0x%08x, computed 0x%08x\n", data_word, crc);
    }
  else
    {
      printf("CRC mismatch, file 0x%08x, should be 0x%08x\n", data_word, crc);
      printf("replacing CRC with 0x%08x\n", crc);
      buffered_data = crc;
    }
  crc_reset = true;
}


void reg_write_cmd(uint32_t data_word)
{
  if (debug)
    {
      if (data_word < 0x20)
	{
	  if (cmd_name[data_word])
	    printf("cmd %s\n", cmd_name[data_word]);
	  else
	    printf("unknown cmd 0x%08x\n", data_word);
	}
    }

  if (data_word == 0x07)
    crc_reset = true;
}


void reg_write_idcode(uint32_t data_word)
{
  const char *part_name;
  const part_info_t *pi = find_part_by_idcode(data_word);
  if (pi)
    part_name = pi->name;
  else
    part_name = "unknown";
  printf("idcode 0x%08x: %s\n", data_word, part_name);
  if (replace_idcode)
    {
      printf("replacing idcode with 0x%08x\n", new_idcode);
      buffered_data = new_idcode;
    }
}


void write_reg_data(uint32_t data_word)
{
  switch (register_address)
    {
    case 0x00: // crc
      reg_write_crc(data_word);
      break;
    case 0x04: // cmd
      reg_write_cmd(data_word);
      break;
    case 0x0c: // idcode
      reg_write_idcode(data_word);
      break;
    }
}


void process_packet_type_1(size_t packet_offset, uint32_t first_word)
{
  opcode = (first_word >> 27) & 3;
  register_address = (first_word >> 13) & 0x1f;
  uint32_t word_count = (first_word & 0x7ff);

  if (word_count > 1)
    fatal(2, "packet type 1 with word count %d", word_count);

  switch (opcode)
    {
    case 0:  // nop
      if (word_count != 0)
	fatal(2, "NOP with non-zero word count %d", word_count);
      break;
    case 1:  // read
      if (debug)
	printf("%zu 0x%08x: read reg 0x%02x %s\n", packet_offset, first_word, register_address, reg_info[register_address].name);
      break;
    case 2:  // write
      if (debug)
	printf("%zu 0x%08x: write reg 0x%02x %s, %d words\n", packet_offset, first_word, register_address, reg_info[register_address].name, word_count);
      break;
    default:
      fatal(2, "unrecognized opcode %d", opcode);
    }

  while (word_count--)
    {
      buffered_data = read_uint(4);
      if (opcode == 0x02)
	write_reg_data(buffered_data);
      update_crc(register_address, buffered_data);
      write_uint(4, buffered_data);
    }
}


void process_packet_type_2(size_t packet_offset, uint32_t first_word)
{
  uint32_t word_count = first_word & 0x7ffffff;
  if (debug)
    printf("%zu: type 2 packet, %u data words\n", packet_offset, word_count);
  while (word_count--)
    {
      buffered_data = read_uint(4);
      if (opcode == 0x02)
	write_reg_data(buffered_data);
      update_crc(register_address, buffered_data);
      write_uint(4, buffered_data);
    }
}


void read_bitstream(size_t config_end_offset)
{
  crc = 0;
  crc_reset = false;
  crc_error = false;
  while (true)
    {
      size_t packet_offset = get_offset();
      if (packet_offset == config_end_offset)
	return;
      uint32_t word = rw_uint(4);
      uint32_t packet_type = word >> 29;
      switch (packet_type)
	{
	case 1: process_packet_type_1(packet_offset, word); break;
	case 2: process_packet_type_2(packet_offset, word); break;
	default: fatal(2, "unknown packet type %u", packet_type);
	}
    }
}


void xchange(void)
{
  uint32_t config_len;
  size_t config_end_offset;

  read_bit_header(& config_len);
  config_end_offset = get_offset() + config_len;

  read_sync_word();

  read_bitstream(config_end_offset);
}


int main(int argc, char *argv[])
{
  char *infn = NULL;
  char *outfn = NULL;

  int c;

  progname = argv[0];
  debug = 0;

  while ((c = getopt(argc, argv, "dp:i:k:o:")) != -1)
    switch (c)
      {
      case 'd':
	debug++;
	break;
      case 'p':
	partnum_str = optarg;
	break;
      case 'i':
	idcode_str = optarg;
	break;
      case 'k':
	package_str = optarg;
	break;
      case 'o':
	outfn = optarg;
	break;
      case '?':
	if ((optopt == 'p') || (optopt == 'i') || (optopt == 'k') || (optopt == 'o'))
	  fatal(1, "Option -%c requires an argument.", optopt);
	if (isprint(optopt))
	  fatal(1, "Unknown option '-%c'", optopt);
	fatal(1, "Unknown option character '\\x%02x'", optopt);
      default:
	abort();
      }

  if (idcode_str)
    {
      char *endptr;
      uint32_t val = strtoul(idcode_str, & endptr, 0);
      if (! endptr[0])
	fatal(2, "idcode syntax error");
      new_idcode = val;
      replace_idcode = true;
      if (! partnum_str)
	{
	  const part_info_t *pi = find_part_by_idcode(new_idcode);
	  if (pi)
	    partnum_str = pi->name;
	  else
	    fatal(2, "unrecognized idcode, must also specify part number");
	}
    }

  if (partnum_str)
    {
      if (! replace_idcode)
	{
	  const part_info_t *pi = find_part_by_part_number(partnum_str);
	  if (pi)
	    {
	      new_idcode = pi->idcode;
	      replace_idcode = true;
	    }
	  else
	    fatal(2, "unrecognized part number, must also specify idcode");
	}
    }

  for (int index = optind; index < argc; index++)
    {
      if (! infn)
	infn = argv[index];
      else
	fatal(1, "Too many arguments given.");
    }

  if (!infn)
    fatal(1, "No input file specified.");
  inf = fopen(infn, "rb");
  if (! inf)
    fatal(2, "error opening input file");

  if (outfn)
    {
      outf = fopen(outfn, "wb");
      if (! outf)
	fatal(2, "error opening output file");
    }

  xchange();

  if (crc_error && ! outf)
    fatal(2, "CRC error(s) detected");

  return 0;
}
