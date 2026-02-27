/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// same file as rust/src/applayertemplate/parser.rs except this comment

use nom7::{
    bytes::streaming::{take, take_until},
    combinator::map_res,
    IResult,
    number::streaming::{be_u16, be_u8},
};
use std;

#[derive(PartialEq, Eq, Debug)]
pub struct COAPFrameHeader {
    //we could add detection on (GOAWAY) additional data
    pub version: u8,
    pub ftype: u8,
    pub token_length: u8,
    pub code: u8,
    pub message_id: u16,
}

pub fn parse_frame_header(i: &[u8]) -> IResult<&[u8], COAPFrameHeader> {
    let (i, data0) = be_u8(i)?;
    let (i, code) = be_u8(i)?;
    let (i, message_id) = be_u16(i)?;
    let version = data0 >> 6;
    let ftype = (data0 >> 4) & 0x03;
    let token_length = data0 & 0x0f;
    Ok((
        i,
        COAPFrameHeader {
            version,
            ftype,
            token_length,
            code,
            message_id,
        },
    ))
}

fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

pub(super) fn parse_message(i: &[u8]) -> IResult<&[u8], String> {
    let (i, len) = map_res(map_res(take_until(":"), std::str::from_utf8), parse_len)(i)?;
    let (i, _sep) = take(1_usize)(i)?;
    let (i, msg) = map_res(take(len as usize), std::str::from_utf8)(i)?;
    let result = msg.to_string();
    Ok((i, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf = b"12:Hello World!4:Bye.";

        let result = parse_message(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message, "Hello World!");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 6);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
}
