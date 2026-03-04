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

use super::coap::*;
use nom7::{
    IResult,
    bytes::streaming::take,
    number::streaming::{be_u16, be_u8},
};

pub struct COAPMessage {
    pub header: COAPHeader,

    pub options: Vec<COAPOption>,

    pub data: Vec<u8>,

    // Set to true if the options were found to be malformed. That is
    // failing to parse with enough data.
    pub malformed_options: bool,

    // Set to true if the options failed to parse due to not enough
    // data.
    pub truncated_options: bool,
}

#[derive(PartialEq, Eq, Debug)]
pub struct COAPHeader {
    pub version: u8,
    pub ftype: u8,
    pub token_length: u8,
    pub code: u8,
    pub message_id: u16,
    pub token: Vec<u8>,
}

pub struct COAPOptContentType {
    pub content_type: u8,
}

pub struct COAPOptGeneric {
    pub data: Vec<u8>,
}

pub enum COAPOptionWrapper {
    ContentType(COAPOptContentType),
    Generic(COAPOptGeneric),
    End,
}

pub struct COAPOption {
    pub code: u16,
    pub data: Option<Vec<u8>>,
    pub option: COAPOptionWrapper,
}

pub fn parse_header(i: &[u8]) -> IResult<&[u8], COAPHeader> {
    let (i, data0) = be_u8(i)?;
    let (i, code) = be_u8(i)?;
    let (i, message_id) = be_u16(i)?;
    let version = data0 >> 6;
    let ftype = (data0 >> 4) & 0x03;
    let token_length = data0 & 0x0f;
    let (i, token) = if token_length > 0 {
        let (i, token) = take(token_length)(i)?;
        (i, token.to_vec())
    } else {
        (i, vec![])
    };
    Ok((
        i,
        COAPHeader {
            version,
            ftype,
            token_length,
            code,
            message_id,
            token,
        },
    ))
}

// Parse a single COAP option. When option 255 (END) is parsed, the remaining
// data will be consumed.
pub fn parse_option(i: &[u8]) -> IResult<&[u8], COAPOption> {
    let (_, opt) = be_u8(i)?;
    if opt == COAP_OPT_END {
        let (_, code) = be_u8(i)?;
        return Ok((i, COAPOption {
            code: code as u16,
            data: None,
            option: COAPOptionWrapper::End,
        }));
    }
    let delta = opt >> 4;
    let code = if delta == 13 {
        let (_, code) = be_u8(i)?;
        (code + 13) as u16
    } else if delta == 14 {
        let (_, code) = be_u16(i)?;
        code + 269
    } else {
        delta as u16
    };
    let length = opt & 0x0f;
    let (i, length) = if length == 13 {
        let (i, length) = be_u8(i)?;
        (i, (length + 13) as u16)
    } else if length == 14 {
        let (i, length) = be_u16(i)?;
        (i, length + 269)
    } else {
        (i, length as u16)
    };
    let (i, data) = take(length)(i)?;
    match code {
        COAP_OPT_CONTENT_TYPE => {
            let (i, content_type) = be_u8(data)?;
            let (_, data) = take(data.len() - 1)(data)?;
            Ok((
                i,
                COAPOption {
                    code,
                    data: Some(data.to_vec()),
                    option: COAPOptionWrapper::ContentType(COAPOptContentType { content_type })
                }
            ))
        }
        _ => {
            Ok((
                i,
                COAPOption {
                    code,
                    data: Some(data.to_vec()),
                    option: COAPOptionWrapper::Generic(COAPOptGeneric {
                        data: data.to_vec(),
                    }),
                },
            ))
        }
    }
}

pub fn parse_coap(input: &[u8]) -> IResult<&[u8], COAPMessage> {
    match parse_header(input) {
        Ok((rem, header)) => {
            let mut options = Vec::new();
            let mut next = rem;
            let malformed_options = false;
            let mut truncated_options = false;
            loop {
                match parse_option(next) {
                    Ok((rem, option)) => {
                        let done = option.code == COAP_OPT_END as u16;
                        options.push(option);
                        next = rem;
                        if done {
                            break;
                        }
                    }
                    Err(_) => {
                        truncated_options = true;
                        break;
                    }
                }
            }
            let message = COAPMessage {
                header,
                options,
                data: next.to_vec(),
                malformed_options,
                truncated_options,
            };
            return Ok((next, message));
        }
        Err(err) => {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf = b"12:Hello World!4:Bye.";

        let result = parse_header(buf);
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
