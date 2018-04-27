/* Team-Hycon
 * Copyright 2018      Team-Hycon  <https://github.com/Team-Hycon>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

class NOTI 
{
public:
    static const int JOB_PREFIX = 0;
    static const int BLOB = 1;
    static const int TARGET = 2;
    static const int JOB_ID = 3;
};

class LEN
{
public:
    static const int BLOB_HEX = 144;
    static const int PREHASH_HEX = 128;
    static const int JOB_PREFIX_HEX = 8;
    static const int NONCE_HEX = 16;
    static const int DIFF_HEX = 16;
    static const int RESULT_HEX = 64;
    
    static const int BLOB = 72;
    static const int PREHASH = 64;
    static const int JOB_PREFIX = 4;
    static const int NONCE = 8;
    static const int DIFF = 8;
    static const int RESULT = 32;

    static const int JOB_ID = 10;
};
#endif