using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using testedobot.Controller;

namespace testedobot
{
    public partial class Form1 : Form
    {

        public Form1()
        {
            InitializeComponent();
        }

    


        private byte[] FileRead(string path)
        {
            try
            {
                //MessageBox.Show(path);
                long length = new FileInfo(path).Length;
                FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buffer = new byte[length];
                stream.Read(buffer, 0, (int)length);
                stream.Flush();
                stream.Close();
                return buffer;
            }
            catch (Exception e)
            {
                MessageBox.Show(e.ToString());
                MessageBox.Show("Erro to decrypt");
                return new byte[3];
            }
        }

        public byte[] Read(string inputFile, byte[] a, byte[] b)
        {

            byte[] sourceArray = FileRead(inputFile);
         

            int count = sourceArray.Length - a.Length;
            byte[] dst = new byte[count];
            Buffer.BlockCopy(sourceArray, a.Length, dst, 0, count);
            var _P = new XXTEA_Decrypt();
            byte[] data = _P.InicializationDecrypt(dst, (uint)count, b, (uint)b.Length, out _);
          //  byte[] data = xxtea_decrypt(dst, (uint)count, b, (uint)b.Length, out _);
            return data;

        }



        private void button1_Click(object sender, EventArgs e)
        {
           

 
            byte[] a = Encoding.ASCII.GetBytes("^G2hbW;UWg)/\\2@q");
            byte[] b = Encoding.ASCII.GetBytes("^_3uz`TG,!");

            var data = Read("sdk_function.luac", b, a);
            string _s = Encoding.UTF8.GetString(data);
           Console.WriteLine(_s.ToString());

        }

     

      

      

       
    }

}
