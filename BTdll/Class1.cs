using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace BTdll
{
    public class BT_Text
    {
        public static char[] Letters = { 'a', 'ą', 'b', 'c', 'ć', 'd', 'e', 'ę', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'ł', 'm', 'n', 'ń', 'o', 'ó', 'p', 'q', 'r', 's', 'ś', 't', 'u', 'v', 'w', 'y', 'z', 'ż', 'x', 'ź' };
        public static char[] Numbers = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };

        public static string ConvertKeyCodeToChar(Key key)
        {
            string _char = "";
            if ((int)key >= 44 && (int)key <= 69)
            {
                _char = key.ToString();
            }
            if (key == Key.D1)
            {
                _char = "1";
            }
            if (key == Key.D2)
            {
                _char = "2";
            }
            if (key == Key.D3)
            {
                _char = "3";
            }
            if (key == Key.D4)
            {
                _char = "4";
            }
            if (key == Key.D5)
            {
                _char = "5";
            }
            if (key == Key.D6)
            {
                _char = "6";
            }
            if (key == Key.D7)
            {
                _char = "7";
            }
            if (key == Key.D8)
            {
                _char = "8";
            }
            if (key == Key.D9)
            {
                _char = "9";
            }
            if (key == Key.D0)
            {
                _char = "0";
            }
            if (key == Key.OemMinus)
            {
                _char = "-";
            }
            if (key == Key.OemPlus)
            {
                _char = "=";
            }
            if (key == Key.OemOpenBrackets)
            {
                _char = "[";
            }
            if (key == Key.Oem6)
            {
                _char = "]";
            }
            if (key == Key.Oem5)
            {
                _char = @"\";
            }
            if (key == Key.Oem1)
            {
                _char = ";";
            }
            if (key == Key.OemQuotes)
            {
                _char = "'";
            }
            if (key == Key.OemQuestion)
            {
                _char = "/";
            }
            if (key == Key.OemPeriod)
            {
                _char = ".";
            }
            if (key == Key.OemComma)
            {
                _char = ",";
            }
            if (key == Key.Oem3)
            {
                _char = "`";
            }
            if (key == Key.NumPad0)
            {
                _char = "0";
            }
            if (key == Key.NumPad1)
            {
                _char = "1";
            }
            if (key == Key.NumPad2)
            {
                _char = "2";
            }
            if (key == Key.NumPad3)
            {
                _char = "3";
            }
            if (key == Key.NumPad4)
            {
                _char = "4";
            }
            if (key == Key.NumPad5)
            {
                _char = "5";
            }
            if (key == Key.NumPad6)
            {
                _char = "6";
            }
            if (key == Key.NumPad7)
            {
                _char = "7";
            }
            if (key == Key.NumPad8)
            {
                _char = "8";
            }
            if (key == Key.NumPad9)
            {
                _char = "9";
            }
            if (key == Key.Divide)
            {
                _char = "/";
            }
            if (key == Key.Multiply)
            {
                _char = "*";
            }
            if (key == Key.Subtract)
            {
                _char = "-";
            }
            if (key == Key.Add)
            {
                _char = "+";
            }
            if (key == Key.Decimal)
            {
                _char = ",";
            }
            return _char;
        }
        public static string ConvertToShiftedChar(char key)
        {
            string _char = "";

            foreach (char letter in Letters)
            {
                if (key.ToString().ToLowerInvariant()[0] == letter)
                {
                    _char = key.ToString().ToUpperInvariant();
                    return _char;
                }
            }

            if (key == '1')
            {
                return "!";
            }
            if (key == '2')
            {
                return "@";
            }
            if (key == '3')
            {
                return "#";
            }
            if (key == '4')
            {
                return "$";
            }
            if (key == '5')
            {
                return "%";
            }
            if (key == '6')
            {
                return "^";
            }
            if (key == '7')
            {
                return "&";
            }
            if (key == '8')
            {
                return "*";
            }
            if (key == '9')
            {
                return "(";
            }
            if (key == '0')
            {
                return ")";
            }
            if (key == '-')
            {
                return "_";
            }
            if (key == '=')
            {
                return "+";
            }
            if (key == '`')
            {
                return "~";
            }
            if (key == '[')
            {
                return "{";
            }
            if (key == ']')
            {
                return "}";
            }
            if (key == @"\"[0])
            {
                return "|";
            }
            if (key == ';')
            {
                return ":";
            }
            if (key == "'"[0])
            {
                return "\"";
            }
            if (key == ',')
            {
                return "<";
            }
            if (key == '.')
            {
                return ">";
            }
            if (key == '/')
            {
                return "?";
            }
            if (_char == "")
            {
                throw new Exception("Sorry, This char can't be shifted. It have to be a usable letter or number or special character.");
            }
            else
            {
                return _char;
            }
        }
        public static string ConvertToAltedChar(char key)
        {
            string _char = "";

            if (key == 'A')
            {
                return "Ą";
            }
            if (key == 'a')
            {
                return "ą";
            }

            if (key == 'E')
            {
                return "Ę";
            }
            if (key == 'e')
            {
                return "ę";
            }

            if (key == 'O')
            {
                return "Ó";
            }
            if (key == 'o')
            {
                return "ó";
            }

            if (key == 'S')
            {
                return "Ś";
            }
            if (key == 's')
            {
                return "ś";
            }

            if (key == 'C')
            {
                return "Ć";
            }
            if (key == 'c')
            {
                return "ć";
            }

            if (key == 'L')
            {
                return "Ł";
            }
            if (key == 'l')
            {
                return "ł";
            }

            if (key == 'Z')
            {
                return "Ż";
            }
            if (key == 'z')
            {
                return "ż";
            }

            if (key == 'X')
            {
                return "Ź";
            }
            if (key == 'x')
            {
                return "ź";
            }

            if (key == 'N')
            {
                return "Ń";
            }
            if (key == 'n')
            {
                return "ń";
            }

            if (_char == "")
            {
                throw new Exception("Sorry, This char can't be alted. It have to be a usable letter.");
            }
            else
            {
                return _char;
            }
        }

        public static string AutoConvertKey(string key, bool ShiftPressed, bool AltPressed, bool CapsLockPressed, bool ThrowBugs)
        {
            string _char = "";
            try
            {
                _char = key.ToLower();

                if (CapsLockPressed)
                {
                    if (ShiftPressed)
                    {
                        if (AltPressed)
                        {
                            _char = ConvertToAltedChar(key[0]);
                        }
                    }
                    else
                    {
                        _char = ConvertToShiftedChar(key[0]);
                        if (AltPressed)
                        {
                            _char = ConvertToAltedChar(key[0]);
                        }
                    }
                }
                else
                {
                    if (ShiftPressed)
                    {
                        _char = ConvertToShiftedChar(key[0]);
                        if (AltPressed)
                        {
                            _char = ConvertToAltedChar(key[0]);
                        }
                    }
                    else
                    {
                        if (AltPressed)
                        {
                            _char = ConvertToAltedChar(key[0]);
                        }
                    }
                }
            }
            catch (Exception es)
            {
                if (ThrowBugs)
                {
                    throw new Exception("Can't analize that letter.", es);
                }
            }
            return _char;
        }
    }
    public class BT_Security
    {
        private void EncryptFile(string inputFile, string outputFile, string password)
        {
            try
            {
                UnicodeEncoding UE = new UnicodeEncoding();
                byte[] key = UE.GetBytes(password);

                string cryptFile = outputFile;
                FileStream fsCrypt = new FileStream(cryptFile, FileMode.Create);
                RijndaelManaged RMCrypto = new RijndaelManaged();
                CryptoStream cs = new CryptoStream(fsCrypt, RMCrypto.CreateEncryptor(key, key), CryptoStreamMode.Write);
                FileStream fsIn = new FileStream(inputFile, FileMode.Open);

                int data;
                while ((data = fsIn.ReadByte()) != -1)
                {
                    cs.WriteByte((byte)data);
                }

                fsIn.Close();
                cs.Close();
                fsCrypt.Close();
            }
            catch (Exception e)
            {
                throw new Exception("Decryption failed!", e);
            }
        }  
        private void DecryptFile(string inputFile, string outputFile, string password)
        {
            try
            {
                UnicodeEncoding UE = new UnicodeEncoding();
                byte[] key = UE.GetBytes(password);

                FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
                RijndaelManaged RMCrypto = new RijndaelManaged();
                CryptoStream cs = new CryptoStream(fsCrypt, RMCrypto.CreateDecryptor(key, key), CryptoStreamMode.Read);
                FileStream fsOut = new FileStream(outputFile, FileMode.Create);

                int data;
                while ((data = cs.ReadByte()) != -1)
                {
                    fsOut.WriteByte((byte)data);
                }
                    
                fsOut.Close();
                cs.Close();
                fsCrypt.Close();
            }
            catch (Exception e)
            {
                throw new Exception("Decryption failed!", e);
            }
        }
    }
    public class BT_Hook
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        public event EventHandler<BT_KeyPressed> OnKeyPressed;

        private LowLevelKeyboardProc _proc;
        private IntPtr _hookID = IntPtr.Zero;

        public BT_Hook()
        {
            _proc = HookCallback;
        }

        public void HookKeyboard()
        {
            _hookID = SetHook(_proc);
        }

        public void UnHookKeyboard()
        {
            UnhookWindowsHookEx(_hookID);
        }

        private IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);

                if (OnKeyPressed != null) { OnKeyPressed(this, new BT_KeyPressed(KeyInterop.KeyFromVirtualKey(vkCode))); }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
    }
    public class BT_KeyPressed : EventArgs
    {
        public Key KeyPressed { get; private set; }

        public BT_KeyPressed(Key key)
        {
            KeyPressed = key;
        }
    }
    public class BT_Keys
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
        public static extern short GetKeyState(int keyCode);

        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int keyCode);

        public static bool IsCapsLockPressed = (((ushort)GetKeyState(0x14)) & 0xffff) != 0;
        public static bool IsAltPressed = !((GetAsyncKeyState(0x12) & (1 << 16)) > 0);
        public static bool IsShiftPressed = !((GetAsyncKeyState(0xA0) & (1 << 16)) > 0) || !((GetAsyncKeyState(0xA1) & (1 << 16)) > 0);
    }
}
