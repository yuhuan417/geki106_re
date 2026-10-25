# Ground truth for page-1 copyright text: replicate 0x44D330 (CreateFontIndirectA + TextOutA)
# with the LOGFONT taken verbatim from 0x4A40F8, on the real Windows host.
#
# Run from WSL:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File probe_gdi_text.ps1 -OutDir C:\Temp\geki
# Outputs: probe.txt (chosen face + TEXTMETRIC), gdi_p1.png (640x480 ground truth)
# NOTE: keep this file pure ASCII: Windows PowerShell 5.1 reads .ps1 as ANSI without a BOM.
param([string]$OutDir = "C:\Users\Public\geki_gdi")
Add-Type -AssemblyName System.Drawing
$code = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
public class GekiGdi {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
  public struct LOGFONTA {
    public int lfHeight, lfWidth, lfEscapement, lfOrientation, lfWeight;
    public byte lfItalic, lfUnderline, lfStrikeOut, lfCharSet, lfOutPrecision, lfClipPrecision, lfQuality, lfPitchAndFamily;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)] public byte[] lfFaceName;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct TEXTMETRICA {
    public int tmHeight, tmAscent, tmDescent, tmInternalLeading, tmExternalLeading;
    public int tmAveCharWidth, tmMaxCharWidth, tmWeight, tmOverhang, tmDigitizedAspectX, tmDigitizedAspectY;
    public byte tmFirstChar, tmLastChar, tmDefaultChar, tmBreakChar, tmItalic, tmUnderlined,
                tmStruckOut, tmPitchAndFamily, tmCharSet, pad0, pad1;
  }
  [DllImport("gdi32.dll")] public static extern IntPtr CreateFontIndirectA(ref LOGFONTA lf);
  [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleDC(IntPtr h);
  [DllImport("gdi32.dll")] public static extern IntPtr SelectObject(IntPtr dc, IntPtr o);
  [DllImport("gdi32.dll", CharSet=CharSet.Ansi)] public static extern int GetTextFaceA(IntPtr dc, int n, StringBuilder sb);
  [DllImport("gdi32.dll")] public static extern int GetTextMetricsA(IntPtr dc, ref TEXTMETRICA tm);
  [DllImport("gdi32.dll", CharSet=CharSet.Ansi)] public static extern bool TextOutA(IntPtr dc, int x, int y, string s, int n);
  [DllImport("gdi32.dll")] public static extern int SetTextColor(IntPtr dc, int c);
  [DllImport("gdi32.dll")] public static extern int SetBkColor(IntPtr dc, int c);
  [DllImport("gdi32.dll")] public static extern int SetBkMode(IntPtr dc, int m);
  [DllImport("gdi32.dll")] public static extern bool DeleteObject(IntPtr o);
  [DllImport("gdi32.dll")] public static extern bool DeleteDC(IntPtr dc);

  static LOGFONTA Lf(int h, int w) {
    LOGFONTA lf = new LOGFONTA();
    lf.lfFaceName = new byte[32];
    lf.lfHeight = h; lf.lfWidth = w;
    lf.lfWeight = 0;            // FW_DONTCARE
    lf.lfCharSet = 128;         // SHIFTJIS_CHARSET
    lf.lfQuality = 0;           // DEFAULT_QUALITY
    lf.lfPitchAndFamily = 1;    // FIXED_PITCH | FF_DONTCARE
    byte[] face = Encoding.GetEncoding(932).GetBytes("MS Mincho (SJIS fullwidth)");
    face = new byte[] { 0x82, 0x6C, 0x82, 0x72, 0x20, 0x96, 0xBE, 0x92, 0xA9 };
    Array.Copy(face, lf.lfFaceName, face.Length);
    return lf;
  }

  public static void Run(string outDir) {
    Directory.CreateDirectory(outDir);
    StringBuilder log = new StringBuilder();
    foreach (int h in new int[] { 16, 32 }) {
      LOGFONTA lf = Lf(h, h / 2);
      IntPtr dc = CreateCompatibleDC(IntPtr.Zero);
      IntPtr f = CreateFontIndirectA(ref lf);
      IntPtr old = SelectObject(dc, f);
      StringBuilder sb = new StringBuilder(64);
      GetTextFaceA(dc, 64, sb);
      TEXTMETRICA tm = new TEXTMETRICA();
      GetTextMetricsA(dc, ref tm);
      log.AppendFormat("lfHeight={0} lfWidth={1} -> face=[{2}] tmHeight={3} asc={4} desc={5} intLead={6} aveW={7} maxW={8} charset={9} pitchfam={10}\r\n",
        h, h / 2, sb.ToString(), tm.tmHeight, tm.tmAscent, tm.tmDescent, tm.tmInternalLeading,
        tm.tmAveCharWidth, tm.tmMaxCharWidth, tm.tmCharSet, tm.tmPitchAndFamily);
      SelectObject(dc, old); DeleteObject(f); DeleteDC(dc);
    }
    File.WriteAllText(Path.Combine(outDir, "probe.txt"), log.ToString());

    Bitmap bmp = new Bitmap(640, 480, PixelFormat.Format24bppRgb);
    Graphics g = Graphics.FromImage(bmp);
    g.Clear(Color.FromArgb(0, 0, 255));
    IntPtr dc2 = g.GetHdc();
    LOGFONTA lf2 = Lf(16, 8);
    IntPtr f2 = CreateFontIndirectA(ref lf2);
    IntPtr old2 = SelectObject(dc2, f2);
    SetBkMode(dc2, 1);
    SetTextColor(dc2, 0x00FEFEFE);
    SetBkColor(dc2, 0x00FF0000);
    string[] top = { "Gekihaden(2) version 1.0", "Copyright 2001,2004 by Tatsuya Miyamoto.", "Over 23431 bytes free" };
    for (int i = 0; i < top.Length; i++) TextOutA(dc2, 32, 32 + 16 * i, top[i], top[i].Length);
    string[] bot = { "color", "auto", "goto", "list", "run" };
    int[] bx = { 32, 147, 262, 377, 492 };
    for (int i = 0; i < bot.Length; i++) TextOutA(dc2, bx[i], 432, bot[i], bot[i].Length);
    SelectObject(dc2, old2); DeleteObject(f2);
    g.ReleaseHdc(dc2); g.Dispose();
    bmp.Save(Path.Combine(outDir, "gdi_p1.png"), ImageFormat.Png);
    bmp.Dispose();
  }
}
'@
Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing
[GekiGdi]::Run($OutDir)
Get-Content (Join-Path $OutDir "probe.txt")
