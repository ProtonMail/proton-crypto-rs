use std::io::{self, Read, Write};

#[allow(dead_code)]
pub fn test_copy<R, W>(reader: &mut R, writer: &mut W, buffer_size: usize) -> io::Result<u64>
where
    R: ?Sized + Read,
    W: ?Sized + Write,
{
    let mut buf = vec![0_u8; buffer_size];
    let mut total_bytes = 0_u64;

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buf[..bytes_read])?;
        total_bytes += bytes_read as u64;
    }

    Ok(total_bytes)
}
