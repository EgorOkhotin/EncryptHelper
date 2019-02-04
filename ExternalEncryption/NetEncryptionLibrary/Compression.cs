using System;
using System.IO;
using System.IO.Compression;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Compression
  {
    public byte[] CompressBytes(CompressionType compressionType, byte[] input)
    {
      try
      {
        MemoryStream input1 = new MemoryStream();
        input1.Write(input, 0, input.Length);
        return this.CompressMemoryStream(compressionType, input1).ToArray();
      }
      catch (Exception ex)
      {
        throw new Exception("Could not compress, check input. Error: " + ex.Message, ex);
      }
    }

    public byte[] DecompressBytes(CompressionType compressionType, byte[] input)
    {
      try
      {
        MemoryStream input1 = new MemoryStream();
        input1.Write(input, 0, input.Length);
        return this.DecompressMemoryStream(compressionType, input1).ToArray();
      }
      catch (Exception ex)
      {
        throw new Exception("Could not decompress, check input. Error: " + ex.Message, ex);
      }
    }

    public MemoryStream CompressMemoryStream(CompressionType compressionType, MemoryStream input)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            return this.GZipCompressMemoryStream(CompressionMode.Compress, input);
          case CompressionType.Deflate:
            return this.DeflateCompressMemoryStream(CompressionMode.Compress, input);
          case CompressionType.MiniLZO:
            return this.MiniLZOCompressMemoryStream(input);
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not compress, check input. Error: " + ex.Message, ex);
      }
    }

    private MemoryStream MiniLZOCompressMemoryStream(MemoryStream input)
    {
      return new MemoryStream(MiniLZO.Compress(input));
    }

    public MemoryStream DecompressMemoryStream(CompressionType compressionType, MemoryStream input)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            return this.GZipDecompressMemoryStream(input);
          case CompressionType.Deflate:
            return this.DeflateDecompressMemoryStream(input);
          case CompressionType.MiniLZO:
            return this.MiniLZODecompressMemoryStream(input);
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not decompress, check input. Error: " + ex.Message, ex);
      }
    }

    private MemoryStream MiniLZODecompressMemoryStream(MemoryStream input)
    {
      return new MemoryStream(MiniLZO.Decompress(input.ToArray()));
    }

    public Stream CompressStream(CompressionType compressionType, Stream input)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            return this.GZipCompressStream(input);
          case CompressionType.Deflate:
            return this.DeflateCompressStream(input);
          case CompressionType.MiniLZO:
            return this.MiniLZOCompressStream(input);
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not compress, check input. Error: " + ex.Message, ex);
      }
    }

    private Stream MiniLZOCompressStream(Stream input)
    {
      MemoryStream source = new MemoryStream();
      byte[] buffer = new byte[10000];
      while (true)
      {
        int count = input.Read(buffer, 0, 10000);
        if (count != 0)
          source.Write(buffer, 0, count);
        else
          break;
      }
      source.Seek(0L, SeekOrigin.Begin);
      return (Stream) new MemoryStream(MiniLZO.Compress(source));
    }

    public Stream DecompressStream(CompressionType compressionType, Stream input)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            return this.GZipDecompressStream(input);
          case CompressionType.Deflate:
            return this.DeflateDecompressStream(input);
          case CompressionType.MiniLZO:
            return this.MiniLZODecompressStream(input);
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not decompress, check input. Error: " + ex.Message, ex);
      }
    }

    private Stream MiniLZODecompressStream(Stream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      byte[] buffer = new byte[10000];
      while (true)
      {
        int count = input.Read(buffer, 0, 10000);
        if (count != 0)
          memoryStream.Write(buffer, 0, count);
        else
          break;
      }
      memoryStream.Seek(0L, SeekOrigin.Begin);
      return (Stream) new MemoryStream(MiniLZO.Decompress(memoryStream.ToArray()));
    }

    public void CompressFile(CompressionType compressionType, string inputFilePath, string outputFilePath)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            this.GZipCompressFile(inputFilePath, outputFilePath);
            break;
          case CompressionType.Deflate:
            this.DeflateCompressFile(inputFilePath, outputFilePath);
            break;
          case CompressionType.MiniLZO:
            this.MiniLZOCompressFile(inputFilePath, outputFilePath);
            break;
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not compress, check input. Error: " + ex.Message, ex);
      }
    }

    private void MiniLZOCompressFile(string inputFilePath, string outputFilePath)
    {
      using (FileStream fileStream1 = new FileStream(inputFilePath, FileMode.Open))
      {
        Stream stream = this.MiniLZOCompressStream((Stream) fileStream1);
        stream.Seek(0L, SeekOrigin.Begin);
        using (FileStream fileStream2 = new FileStream(outputFilePath, FileMode.Create))
        {
          byte[] buffer = new byte[10000];
          while (true)
          {
            int count = stream.Read(buffer, 0, 10000);
            if (count != 0)
              fileStream2.Write(buffer, 0, count);
            else
              break;
          }
        }
      }
    }

    public void DecompressFile(CompressionType compressionType, string inputFilePath, string outputFilePath)
    {
      try
      {
        switch (compressionType)
        {
          case CompressionType.GZip:
            this.GZipDecompressFile(inputFilePath, outputFilePath);
            break;
          case CompressionType.Deflate:
            this.DeflateDecompressFile(inputFilePath, outputFilePath);
            break;
          case CompressionType.MiniLZO:
            this.MiniLZODecompressFile(inputFilePath, outputFilePath);
            break;
          default:
            throw new NotSupportedException(compressionType.ToString() + " is not supported");
        }
      }
      catch (Exception ex)
      {
        throw new Exception("Could not decompress, check input. Error: " + ex.Message, ex);
      }
    }

    private void MiniLZODecompressFile(string inputFilePath, string outputFilePath)
    {
      using (FileStream fileStream1 = new FileStream(inputFilePath, FileMode.Open))
      {
        Stream stream = this.MiniLZODecompressStream((Stream) fileStream1);
        stream.Seek(0L, SeekOrigin.Begin);
        using (FileStream fileStream2 = new FileStream(outputFilePath, FileMode.Create))
        {
          byte[] buffer = new byte[10000];
          while (true)
          {
            int count = stream.Read(buffer, 0, 10000);
            if (count != 0)
              fileStream2.Write(buffer, 0, count);
            else
              break;
          }
        }
      }
    }

    private MemoryStream GZipCompressMemoryStream(CompressionMode mode, MemoryStream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (GZipStream gzipStream = new GZipStream((Stream) memoryStream, mode))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = input.Read(buffer, 0, 10000);
          if (count != 0)
            gzipStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return memoryStream;
    }

    private MemoryStream DeflateCompressMemoryStream(CompressionMode mode, MemoryStream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (DeflateStream deflateStream = new DeflateStream((Stream) memoryStream, mode))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = input.Read(buffer, 0, 10000);
          if (count != 0)
            deflateStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return memoryStream;
    }

    public MemoryStream DeflateDecompressMemoryStream(MemoryStream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (DeflateStream deflateStream = new DeflateStream((Stream) input, CompressionMode.Decompress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = deflateStream.Read(buffer, 0, 10000);
          if (count != 0)
            memoryStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return memoryStream;
    }

    public MemoryStream GZipDecompressMemoryStream(MemoryStream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (GZipStream gzipStream = new GZipStream((Stream) input, CompressionMode.Decompress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = gzipStream.Read(buffer, 0, 10000);
          if (count != 0)
            memoryStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return memoryStream;
    }

    private Stream GZipCompressStream(Stream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (GZipStream gzipStream = new GZipStream((Stream) memoryStream, CompressionMode.Compress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = input.Read(buffer, 0, 10000);
          if (count != 0)
            gzipStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return (Stream) memoryStream;
    }

    private Stream DeflateCompressStream(Stream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (DeflateStream deflateStream = new DeflateStream((Stream) memoryStream, CompressionMode.Compress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = input.Read(buffer, 0, 10000);
          if (count != 0)
            deflateStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return (Stream) memoryStream;
    }

    public Stream DeflateDecompressStream(Stream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (DeflateStream deflateStream = new DeflateStream(input, CompressionMode.Decompress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = deflateStream.Read(buffer, 0, 10000);
          if (count != 0)
            memoryStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return (Stream) memoryStream;
    }

    public Stream GZipDecompressStream(Stream input)
    {
      MemoryStream memoryStream = new MemoryStream();
      input.Position = 0L;
      using (GZipStream gzipStream = new GZipStream(input, CompressionMode.Decompress))
      {
        byte[] buffer = new byte[10000];
        while (true)
        {
          int count = gzipStream.Read(buffer, 0, 10000);
          if (count != 0)
            memoryStream.Write(buffer, 0, count);
          else
            break;
        }
      }
      return (Stream) memoryStream;
    }

    private void DeflateCompressFile(string inputFileName, string outputFileName)
    {
      using (FileStream fileStream1 = new FileStream(inputFileName, FileMode.Open))
      {
        using (FileStream fileStream2 = new FileStream(outputFileName, FileMode.Create))
        {
          using (DeflateStream deflateStream = new DeflateStream((Stream) fileStream2, CompressionMode.Compress))
          {
            byte[] buffer = new byte[10000];
            while (true)
            {
              int count = fileStream1.Read(buffer, 0, 10000);
              if (count != 0)
                deflateStream.Write(buffer, 0, count);
              else
                break;
            }
          }
        }
      }
    }

    private void GZipCompressFile(string inputFileName, string outputFileName)
    {
      using (FileStream fileStream1 = new FileStream(inputFileName, FileMode.Open))
      {
        using (FileStream fileStream2 = new FileStream(outputFileName, FileMode.Create))
        {
          using (GZipStream gzipStream = new GZipStream((Stream) fileStream2, CompressionMode.Compress))
          {
            byte[] buffer = new byte[10000];
            while (true)
            {
              int count = fileStream1.Read(buffer, 0, 10000);
              if (count != 0)
                gzipStream.Write(buffer, 0, count);
              else
                break;
            }
          }
        }
      }
    }

    public void GZipDecompressFile(string inputFileName, string outputFileName)
    {
      using (FileStream fileStream1 = new FileStream(inputFileName, FileMode.Open))
      {
        using (FileStream fileStream2 = new FileStream(outputFileName, FileMode.Create))
        {
          using (GZipStream gzipStream = new GZipStream((Stream) fileStream1, CompressionMode.Decompress))
          {
            byte[] buffer = new byte[10000];
            while (true)
            {
              int count = gzipStream.Read(buffer, 0, 10000);
              if (count != 0)
                fileStream2.Write(buffer, 0, count);
              else
                break;
            }
          }
        }
      }
    }

    public void DeflateDecompressFile(string inputFileName, string outputFileName)
    {
      using (FileStream fileStream1 = new FileStream(inputFileName, FileMode.Open))
      {
        using (FileStream fileStream2 = new FileStream(outputFileName, FileMode.Create))
        {
          using (DeflateStream deflateStream = new DeflateStream((Stream) fileStream1, CompressionMode.Decompress))
          {
            byte[] buffer = new byte[10000];
            while (true)
            {
              int count = deflateStream.Read(buffer, 0, 10000);
              if (count != 0)
                fileStream2.Write(buffer, 0, count);
              else
                break;
            }
          }
        }
      }
    }
  }
}
