using System;

namespace testedobot.Controller
{
    /**
     * XXTEA_Decrypt
     * @author Skillerm<CastroMS>
     * @discord CastroMS#3430
     * @mail skillerm.cm@gmail.com
     * 2022/12/18
     */
    internal class XXTEA_Decrypt
    {

        uint DELTA = 0x9e3779B9;

        /**
          * InicializationDecrypt
          * 
          */
    public byte[] InicializationDecrypt(byte[] data, uint data_len, byte[] key, uint key_len, out uint ret_length)
        {
            // Initialize the return length to 0
            ret_length = 0;

            // If the key length is less than 0x10 (16), fix the key length by adding 0s to the end of the key
            // Otherwise, use the original key
            byte[] fixed_key = (key_len < 0x10) ? this.fix_key_length(key, key_len) : key;

            // Decrypt the data using the fixed key and return the decrypted data
            // Also, set the return length to the length of the decrypted data
            byte[] decryptedData = this.XXTEA_Decry(data, data_len, fixed_key, out ret_length);
            return decryptedData;
        }

        private byte[] XXTEA_Decry(byte[] data, uint len, byte[] key, out uint ret_len)
        {
            // Convert the data and key into arrays of unsigned integers
            uint[] v = this.XXTEA_LongArray(data, len, 0, out uint num);
            uint[] k = this.XXTEA_LongArray(key, 0x10, 0, out _);

            // Decrypt the data using the key
            this.XXTEA_Decry_Long(ref v, num, ref k);

            // Convert the decrypted data back into a byte array and set the return length to the length of the decrypted data
            return this.XXTEA_ByteArray(v, num, 1, out ret_len);
        }


        // This function creates a new array (fixed_key) of 16 bytes (0x10) and copies the contents of the input array (key)
        // into it, up to a maximum of "key_len" bytes.
        private byte[] fix_key_length(byte[] key, uint key_len)
        {
            // Initialize a new array of 16 bytes
            byte[] fixed_key = new byte[0x10];

            // Copy the contents of the input array (key) into the new array (fixed_key), up to a maximum of "key_len" bytes
            Array.Copy(key, fixed_key, (long)key_len);

            // Return the new array
            return fixed_key;
        }


        // This function decrypts an array of 32-bit unsigned integers (v) of length "len"
        // using the key (k) provided.
        private void XXTEA_Decry_Long(ref uint[] v, uint len, ref uint[] k)
        {
            // Initialize the index to the last element in the array
            uint index = len - 1;

            // Initialize num2 to the last element in the array
            uint num2 = v[index];

            // Initialize num3 to the first element in the array
            uint num3 = v[0];

            // Initialize num6 to a constant value that is used in the decryption process
            uint num6 = (uint)((6 + (0x34 / (index + 1))) * -1_640_531_527);

            // Continue decrypting until num6 is 0
            while (num6 != 0)
            {
                // Calculate the value of num7, which is used in the decryption process
                uint num7 = (num6 >> 2) & 3;

                // Initialize num4 to the value of index
                uint num4 = index;

                // Continue decrypting until num4 is 0
                while (num4 != 0)
                {
                    // Set num2 to the element in the array at the previous index
                    num2 = v[((int)num4) - 1];

                    // Decrypt the current element in the array (num4) by using the previous element (num2)
                    // and the current element (num3) in the decryption process
                    num3 = v[num4] -= (((num2 >> 5) ^ (num3 << 2)) + ((num3 >> 3) ^ (num2 << 4))) ^ ((num6 ^ num3) + (k[(num4 & 3) ^ num7] ^ num2));

                    // Decrement num4
                    num4--;
                }

                // Set num2 to the last element in the array
                num2 = v[index];

                // Decrypt the first element in the array by using the last element (num2)
                // and the current element (num3) in the decryption process
                num3 = v[0] -= (((num2 >> 5) ^ (num3 << 2)) + ((num3 >> 3) ^ (num2 << 4))) ^ ((num6 ^ num3) + (k[(num4 & 3) ^ num7] ^ num2));

                // Decrement num6
                num6 -= this.DELTA; //0x9e3779b9 //0x464C457F
            }
        }




        // This function converts an array of 32-bit unsigned integers (data) of length "len"
        // into an array of bytes, and returns the resulting array.
        // If "include_length" is set to 1, the length of the input array is included in the output.
        // The length of the returned array is stored in the "ret_len" output parameter.
        private byte[] XXTEA_ByteArray(uint[] data, uint len, int include_length, out uint ret_len)
        {
            // Initialize ret_len to 0
            ret_len = 0;

            // Calculate the length of the output array in bytes
            uint num2 = len << 2;

            // If include_length is set to 1, check if the last element in the input array
            // contains the length of the array, and if so, set num2 to that value
            if (include_length == 1)
            {
                uint num3 = data[((int)len) - 1];
                if ((num3 >= (num2 - 7)) && (num3 <= (num2 - 4)))
                {
                    num2 = num3;
                }
                else
                {
                    // Return null if the last element in the input array does not contain the length of the array
                    return null;
                }
            }

            // Initialize a new array of bytes with a length of num2
            byte[] buffer = new byte[num2];

            // Initialize the index to 0
            uint index = 0;

            // Continue converting the input array to bytes until the index is equal to num2
            while (index < num2)
            {
                // Convert the current element in the input array to a byte and store it in the output array
                buffer[index] = (byte)((data[index >> 2] >> (((int)(index & 3) << 3) & 0x1f)) & 0xff);

                // Increment the index
                index++;
            }

            // Store the length of the output array in ret_len
            ret_len = num2;

            // Return the output array
            return buffer;
        }




        // This function converts an array of bytes (data) of length "len"
        // into an array of 32-bit unsigned integers, and returns the resulting array.
        // If "include_length" is set to 1, the length of the input array is included in the output.
        // The length of the returned array is stored in the "ret_len" output parameter.
        private uint[] XXTEA_LongArray(byte[] data, uint len, int include_length, out uint ret_len)
        {
            // Initialize an array of 32-bit unsigned integers
            uint[] numArray;

            // Calculate the number of 32-bit unsigned integers in the input array
            uint index = len >> 2;
            index = ((len & 3) == 0) ? index : (index + 1);

            // If include_length is set to 1, initialize the array with an additional element to store the length of the input array
            if (include_length != 1)
            {
                numArray = new uint[index << 2];
                ret_len = index;
            }
            else
            {
                numArray = new uint[(index + 1) << 2];
                numArray[index] = len;
                ret_len = index + 1;
            }

            // Convert the input array to 32-bit unsigned integers and store them in the output array
            for (uint i = 0; i < len; i += 4)
            {
                numArray[i >> 2] = BitConverter.ToUInt32(data, (int)i);
            }

            // Return the output array
            return numArray;
        }


        /**
         * Encode Area
         * ============================================================================
         */
        public byte[] InicializationEncrypt(byte[] data, uint data_len, byte[] key, uint key_len, out uint ret_length)
        {

            ret_length = 0;
            byte[] fixed_key = (key_len < 0x10) ? this.fix_key_length(key, key_len) : key;
            return this.XXTEAA_Encrypt(data, data_len, fixed_key, out ret_length);
        }


        private byte[] XXTEAA_Encrypt(byte[] data, uint len, byte[] key, out uint ret_len)
        {
            uint[] v = this.XXTEA_LongArray(data, len, 1, out uint num);
            uint[] k = this.XXTEA_LongArray(key, 0x10, 0, out _);
            this.XXTEA_Encrypt_Long(ref v, num, ref k);
            return this.XXTEA_ByteArray(v, num, 0, out ret_len);
        }

        // This function encrypts an array of 32-bit unsigned integers (v) of length "len"
        // using the key (k) provided.
        private void XXTEA_Encrypt_Long(ref uint[] v, uint len, ref uint[] k)
        {
            // Initialize the index to the last element in the array
            uint index = len - 1;

            // Initialize num2 to the last element in the array
            uint num2 = v[index];

            // Initialize num3 to the first element in the array
            uint num3 = v[0];

            // Initialize num5 to a constant value that is used in the encryption process
            uint num5 = 6 + (0x34 / (index + 1));

            // Initialize num6 to 0
            uint num6 = 0;

            // If the length of the array is greater than or equal to 1, perform the encryption
            if (index >= 1)
            {
                // Encrypt the array num5 times
                for (uint i = 0; i < num5; i++)
                {
                    // Increment num6
                    num6 += this.DELTA;

                    // Encrypt each element in the array, except for the last element
                    for (uint j = 0; j < index; j++)
                    {
                        // Set num3 to the element in the array at the next index
                        num3 = v[j + 1];

                        // Encrypt the current element in the array (j) by using the next element (num3)
                        // and the current element (num2) in the encryption process
                        num2 = v[j] += (((num2 >> 5) ^ (num3 << 2)) + ((num3 >> 3) ^ (num2 << 4))) ^ ((num6 ^ num3) + (k[j & 3] ^ num2));
                    }

                    // Set num3 to the first element in the array
                    num3 = v[0];

                    // Encrypt the last element in the array by using the first element (num3)
                    // and the current element (num2) in the encryption process
                    num2 = v[index] += (((num2 >> 5) ^ (num3 << 2)) + ((num3 >> 3) ^ (num2 << 4))) ^ ((num6 ^ num3) + (k[index & 3] ^ num2));
                }
            }
        }

    }
}
