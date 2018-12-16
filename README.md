# xchange - verify or change idcode and/or CRC of Xilinx FPGA bitstream files

Hosted at the
[xchange Github repository](https://github.com/brouhaha/xchange/).

## Introduction

xchange can verify the idcode (FPGA chip ID) and CRC of a Xilinx
FPGA bitstream file, and optionally correct a bad CRC. It can also
change the idcode.

## WARNING

Changing the contents of the bitstream to force it to load into the "wrong"
FPGA could potentially damage the FPGA. There is no warranty, and the author
disclaims all liability for such damage.

## Examples

* `xchange ham.bit`

  Displays the idcode and verifies the CRC of the ham bitstream.

* `xchange ham.bit -o eggs.bit`

  Copies the ham bitstream to a new eggs bitstream, correcting the CRC if
  needed.

* `xchange -p xc7a15t ham.bit -o eggs.bit`

  Copies the ham bistream, which might e.g. be a bistream generated for an
  XC7A50T FPGA, to a new eggs bitstream, changing the idcode to
  that of the XC7A15T FPGA, and updating the CRC.

## License

Copyright 2018 Eric Smith <spacewar@gmail.com>

SPDX-License-Identifier: GPL-3.0-only

This program is free software: you can redistribute it and/or modify
it under the terms of version 3 of the GNU General Public License
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
