use std::str;
use nom::*;

#[derive(Debug)]
pub enum Message<'a> {
    Query(&'a str),

    Parse {
        statement:   &'a str,
        query:       &'a str,
        param_types: Vec<i32>,
    },

    ParseComplete,

    Describe {
        what: u8,
        name: &'a str,
    },

    ParameterDescription {
        types: Vec<i32>,
    },

    ParameterStatus {
        name:  &'a str,
        value: &'a str,
    },

    RowDescription {
        fields: Vec<Field<'a>>
    },

    ReadyForQuery(u8),

    Bind {
        portal_name:    &'a str,
        statement_name: &'a str,
        param_formats:  Vec<u16>,
        param_values:   Vec<Option<&'a [u8]>>,
    },

    BindComplete,

    Execute {
        portal_name:    &'a str,
        max_rows:       u32,
    },

    DataRow {
        column_values: Vec<Option<&'a [u8]>>,
    },

    CommandComplete(&'a str),
    EmptyQueryResponse,
    NoData,

    Close {
        what: u8,
        name: &'a str,
    },

    CloseComplete,

    Sync,
    Flush,
    Terminate,

    Authentication(Auth<'a>),

    BackendKeyData {
        process_id: i32,
        secret_key: i32,
    },

    Error(u8),

    Unknown {
        tag: u8,
        len: i32,
        data: &'a [u8],
    }
}

#[derive(Debug)]
pub struct Field<'a> {
    name: &'a str,
}

#[derive(Debug)]
pub enum Auth<'a> {
    Ok,
    KerberosV5,
    Cleartext,
    MD5(&'a [u8]) ,
    SCM,
    GSS,
    SSPI,
    GSSContinue(&'a [u8]),
}

named!(pub parse_frontend<&[u8],Vec<Message>>,
       many1!(alt!(
           query                 |
           parse                 |
           describe              |
           bind                  |
           execute               |
           close                 |
           sync                  |
           flush                 |
           terminate             |
           unknown))
);

named!(pub parse_backend<&[u8],Vec<Message>>,
       many1!(alt!(
           authentication        |
           parse_complete        |
           parameter_description |
           parameter_status      |
           row_description       |
           ready_for_query       |
           bind_complete         |
           data_row              |
           command_complete      |
           close_complete        |
           empty_query_response  |
           no_data               |
           error_response        |
           backend_key_data      |
           unknown))
);

named!(authentication<&[u8],Message>,
       do_parse!(
              tag!("R")
           >> len:   be_i32
           >> code:  be_i32
           >> extra: take!(len as usize - 8)
           >> (Message::Authentication(match code {
               0 => Auth::Ok,
               2 => Auth::KerberosV5,
               3 => Auth::Cleartext,
               5 => Auth::MD5(extra),
               6 => Auth::SCM,
               7 => Auth::GSS,
               8 => Auth::GSSContinue(extra),
               9 => Auth::SSPI,
               _ => unreachable!(),
           }))
       )
);

named!(query<&[u8],Message>,
       do_parse!(
              tag!("Q")
           >> len:   be_i32
           >> query: c_string
           >> (Message::Query(query))
       )
);

named!(parse<&[u8],Message>,
       do_parse!(
              tag!("P")
           >> len:       be_i32
           >> statement: c_string
           >> query:     c_string
           >> types:     length_count!(be_i16, be_i32)
           >> (Message::Parse {
               statement: statement,
               query:     query,
               param_types: types,
           })
       )
);

named!(parse_complete<&[u8],Message>,
       do_parse!(tag!("1") >> skip_rest >> (Message::ParseComplete))
);

named!(describe<&[u8],Message>,
       do_parse!(
              tag!("D")
           >> len:   be_i32
           >> what:  be_u8
           >> name:  c_string
           >> (Message::Describe {
               what: what,
               name: name,
           })
       )
);

named!(parameter_description<&[u8],Message>,
       do_parse!(
              tag!("t")
           >> len:   be_i32
           >> types: length_count!(be_i16, be_i32)
           >> (Message::ParameterDescription {
               types: types,
           })
       )
);

named!(parameter_status<&[u8],Message>,
       do_parse!(
              tag!("S")
           >> len:   be_i32
           >> name:  c_string
           >> value: c_string
           >> (Message::ParameterStatus {
               name:  name,
               value: value,
           })
       )
);

named!(row_description<&[u8],Message>,
       do_parse!(
              tag!("T")
           >> len:    be_i32
           >> fields: length_count!(be_i16, field)
           >> (Message::RowDescription {
               fields: fields,
           })
       )
);

named!(field<&[u8],Field>,
       do_parse!(
              name:                   c_string
           >> origin_table_oid:       be_i32
           >> origin_column_attr_num: be_i16
           >> type_oid:               be_i32
           >> type_size:              be_i16
           >> type_mod:               be_i32
           >> format:                 be_i16
           >> (Field { name: name })
       )
);

named!(ready_for_query<&[u8],Message>,
       do_parse!(
              tag!("Z")
           >> len:    be_i32
           >> status: be_u8
           >> (Message::ReadyForQuery(status))
       )
);

named!(bind<&[u8],Message>,
       do_parse!(
              tag!("B")
           >> len:            be_i32
           >> portal_name:    c_string
           >> statement_name: c_string
           >> param_formats:  length_count!(be_i16, be_u16)
           >> param_values:   length_count!(be_i16, value)
           >> result_formats: length_count!(be_i16, be_u16)
           >> (Message::Bind {
               portal_name:    portal_name,
               statement_name: statement_name,
               param_formats:  param_formats,
               param_values:   param_values,
           })
       )
);

named!(bind_complete<&[u8],Message>,
       do_parse!(tag!("2") >> skip_rest >> (Message::BindComplete))
);

named!(command_complete<&[u8],Message>,
       do_parse!(
              tag!("C")
           >> len: be_i32
           >> tag: c_string
           >> (Message::CommandComplete(tag))
       )
);

named!(empty_query_response<&[u8],Message>,
       do_parse!(tag!("I") >> skip_rest >> (Message::EmptyQueryResponse))
);

named!(no_data<&[u8],Message>, do_parse!(tag!("n") >> skip_rest >> (Message::NoData)));

named!(error_response<&[u8],Message>,
       do_parse!(
              tag!("E")
           >> len:    be_i32
           >> code:   be_u8
           >> fields: take!(len as usize - 5)
           >> (Message::Error(code))
       )
);

named!(execute<&[u8],Message>,
       do_parse!(
              tag!("E")
           >> len:         be_i32
           >> portal_name: c_string
           >> max_rows:    be_i32
           >> (Message::Execute {
               portal_name: portal_name,
               max_rows: max_rows as u32,
           })
       )
);

named!(close<&[u8],Message>,
       do_parse!(
              tag!("C")
           >> len:  be_i32
           >> what: be_u8
           >> name: c_string
           >> (Message::Close {
               what: what,
               name: name,
           })
       )
);

named!(data_row<&[u8],Message>,
       do_parse!(
              tag!("D")
           >> len:    be_i32
           >> values: length_count!(be_i16, value)
           >> (Message::DataRow {
               column_values: values,
           })
       )
);

named!(value<&[u8],Option<&[u8]>>,
       do_parse!(
              len:  be_i32
           >> data: cond!(len >= 0, take!(len))
           >> (data)
       )
);

named!(sync<&[u8],Message>, do_parse!(tag!("S") >> skip_rest >> (Message::Sync)));
named!(flush<&[u8],Message>, do_parse!(tag!("H") >> skip_rest >> (Message::Flush)));
named!(terminate<&[u8],Message>, do_parse!(tag!("X") >> skip_rest >> (Message::Terminate)));
named!(close_complete<&[u8],Message>, do_parse!(tag!("3") >> skip_rest >> (Message::CloseComplete)));

named!(backend_key_data<&[u8],Message>,
       do_parse!(
              tag!("K")
           >> len:         be_i32
           >> process_id:  be_i32
           >> secret_key:  be_i32
           >> (Message::BackendKeyData {
               process_id: process_id,
               secret_key: secret_key,
           })
       )
);

named!(unknown<&[u8],Message>,
       do_parse!(
              tag: be_u8
           >> len: be_i32
           >> data: take!((len as usize).saturating_sub(4))
           >> (Message::Unknown {
               tag: tag,
               len: len,
               data: data,
           })
       )
);

named!(c_string<&[u8],&str>,
       map_res!(take_until_and_consume!("\0"), str::from_utf8)
);

named!(skip_rest<&[u8],()>,
       do_parse!(len: be_i32 >> take!((len as usize).saturating_sub(4)) >> ())
);
