#ifndef CRC16C_BR_H
#define CRC16C_BR_H

// bit-reversed CRC-32C
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

#include <stdint.h>


uint32_t crc32c_br_8(uint32_t crc, uint8_t d);

uint32_t crc32c_br_5(uint32_t crc, uint8_t d);

#endif // CRC16C_BR_H
