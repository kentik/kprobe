// This is a copy of nom 3.2.1's named_args macro, modified to support return values
// with a lifetime tied to the input buffer lifetime. This was the default in nom 2
// but modified in nom 3+ to separate the input and output lifetimes.
//
// This DNS parser outputs structs with references to the input and using named_args
// is more convenient than a full function definition, thus this macro. However it
// must be updated alongside any nom upgrades that change the original definition.

#[macro_export]
macro_rules! knamed_args {
    (pub $func_name:ident ( $( $arg:ident : $typ:ty ),* ) < $return_type:ty > , $submac:ident!( $($args:tt)* ) ) => {
        pub fn $func_name(input: &[u8], $( $arg : $typ ),*) -> ::nom::IResult<&[u8], $return_type> {
            $submac!(input, $($args)*)
        }
    };
    (pub $func_name:ident < 'a > ( $( $arg:ident : $typ:ty ),* ) < $return_type:ty > , $submac:ident!( $($args:tt)* ) ) => {
        pub fn $func_name<'a>(input: &'a [u8], $( $arg : $typ ),*) -> ::nom::IResult<&'a [u8], $return_type> {
            $submac!(input, $($args)*)
        }
    };
    ($func_name:ident ( $( $arg:ident : $typ:ty ),* ) < $return_type:ty > , $submac:ident!( $($args:tt)* ) ) => {
        fn $func_name(input: &[u8], $( $arg : $typ ),*) -> ::nom::IResult<&[u8], $return_type> {
            $submac!(input, $($args)*)
        }
    };
    ($func_name:ident < 'a > ( $( $arg:ident : $typ:ty ),* ) < $return_type:ty > , $submac:ident!( $($args:tt)* ) ) => {
        fn $func_name<'a>(input: &'a [u8], $( $arg : $typ ),*) -> ::nom::IResult<&'a [u8], $return_type> {
            $submac!(input, $($args)*)
        }
    };
}
