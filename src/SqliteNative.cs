using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace KotorKPatchAdapter
{
    internal static class SqliteNative
    {
        private const int SQLITE_OK = 0;
        private const int SQLITE_ROW = 100;
        private const int SQLITE_DONE = 101;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_open16([MarshalAs(UnmanagedType.LPWStr)] string filename, out IntPtr db);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close(IntPtr db);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg(IntPtr db);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int sqlite3_prepare_v2(IntPtr db, string sql, int nByte, out IntPtr stmt, IntPtr tail);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr stmt);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr stmt);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long sqlite3_column_int64(IntPtr stmt, int col);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int sqlite3_exec(IntPtr db, string sql, IntPtr callback, IntPtr arg, out IntPtr errmsg);

        [DllImport("sqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void sqlite3_free(IntPtr p);

        private static string PtrUtf8(IntPtr p)
        {
            if (p == IntPtr.Zero) return "";
            int len = 0;
            while (Marshal.ReadByte(p, len) != 0) len++;
            byte[] bytes = new byte[len];
            Marshal.Copy(p, bytes, 0, len);
            return Encoding.UTF8.GetString(bytes);
        }

        private static void PrepareSqlite(string sqliteDll)
        {
            if (string.IsNullOrEmpty(sqliteDll) || !File.Exists(sqliteDll))
                throw new AdapterException("sqlite3.dll was not found. Select the Kotor Patch Manager folder containing sqlite3.dll.");
            string dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(sqliteDll));
            if (!SetDllDirectory(dir))
                throw new AdapterException("Windows could not add the sqlite3.dll directory to the DLL search path.");
        }

        private static IntPtr Open(string dbPath, string sqliteDll)
        {
            PrepareSqlite(sqliteDll);
            IntPtr db;
            int rc;
            try
            {
                rc = sqlite3_open16(System.IO.Path.GetFullPath(dbPath), out db);
            }
            catch (BadImageFormatException ex)
            {
                throw new AdapterException("sqlite3.dll has the wrong architecture. KOTOR KPatch Adapter is built as x86 so it can use Kotor Patch Manager's x86 sqlite3.dll.", ex);
            }
            catch (DllNotFoundException ex)
            {
                throw new AdapterException("Could not load sqlite3.dll from the selected Patch Manager folder.", ex);
            }
            if (rc != SQLITE_OK)
            {
                string msg = db != IntPtr.Zero ? PtrUtf8(sqlite3_errmsg(db)) : "unknown SQLite error";
                if (db != IntPtr.Zero) sqlite3_close(db);
                throw new AdapterException("Could not open address database: " + msg);
            }
            return db;
        }

        private static string EscapeSql(string s)
        {
            return s.Replace("'", "''");
        }

        private static void Exec(IntPtr db, string sql)
        {
            IntPtr err;
            int rc = sqlite3_exec(db, sql, IntPtr.Zero, IntPtr.Zero, out err);
            if (rc != SQLITE_OK)
            {
                string msg = err != IntPtr.Zero ? PtrUtf8(err) : PtrUtf8(sqlite3_errmsg(db));
                if (err != IntPtr.Zero) sqlite3_free(err);
                throw new AdapterException("SQLite error: " + msg);
            }
        }

        private static List<string[]> Query(IntPtr db, string sql, int columnCount)
        {
            IntPtr stmt;
            int rc = sqlite3_prepare_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (rc != SQLITE_OK) throw new AdapterException("SQLite prepare failed: " + PtrUtf8(sqlite3_errmsg(db)));
            List<string[]> rows = new List<string[]>();
            try
            {
                while (true)
                {
                    rc = sqlite3_step(stmt);
                    if (rc == SQLITE_DONE) break;
                    if (rc != SQLITE_ROW) throw new AdapterException("SQLite query failed: " + PtrUtf8(sqlite3_errmsg(db)));
                    string[] row = new string[columnCount];
                    for (int i = 0; i < columnCount; i++) row[i] = PtrUtf8(sqlite3_column_text(stmt, i));
                    rows.Add(row);
                }
            }
            finally
            {
                sqlite3_finalize(stmt);
            }
            return rows;
        }

        public static DbAnalysis Analyze(string dbPath, string sqliteDll, string exeHash)
        {
            DbAnalysis a = new DbAnalysis();
            a.Integrity = "error";
            try
            {
                IntPtr db = Open(dbPath, sqliteDll);
                try
                {
                    List<string[]> integrityRows = Query(db, "PRAGMA integrity_check", 1);
                    a.Integrity = integrityRows.Count > 0 ? integrityRows[0][0] : "no result";
                    List<string[]> cols = Query(db, "PRAGMA table_info(game_version)", 6);
                    HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string[] r in cols) if (r.Length > 1) names.Add(r[1]);
                    string[] needed = { "id", "sha256_hash", "game_name", "version_string", "description", "platform" };
                    foreach (string n in needed)
                        if (!names.Contains(n)) throw new AdapterException("game_version table does not have the expected KPM schema (missing " + n + ").");
                    List<string[]> versions = Query(db, "SELECT sha256_hash, game_name, version_string FROM game_version ORDER BY id", 3);
                    bool hasKotor1 = false;
                    foreach (string[] r in versions)
                    {
                        if (r.Length >= 3)
                        {
                            a.Versions.Add(r[0] + " | " + r[1] + " | " + r[2]);
                            if (string.Equals(r[1], "KOTOR1", StringComparison.OrdinalIgnoreCase)) hasKotor1 = true;
                            if (string.Equals(r[0], exeHash, StringComparison.OrdinalIgnoreCase)) a.HasHash = true;
                        }
                    }
                    if (!hasKotor1) throw new AdapterException("Database has the expected schema but contains no KOTOR1 version rows.");
                    a.Valid = string.Equals(a.Integrity, "ok", StringComparison.OrdinalIgnoreCase);
                }
                finally { sqlite3_close(db); }
            }
            catch (Exception ex)
            {
                a.Valid = false;
                a.Error = ex.Message;
            }
            return a;
        }

        public static string UpdateInPlace(string dbPath, string sqliteDll, string exeHash)
        {
            DbAnalysis before = Analyze(dbPath, sqliteDll, exeHash);
            if (!before.Valid)
                throw new AdapterException("Address database is not valid for editing: " + (string.IsNullOrEmpty(before.Error) ? before.Integrity : before.Error));

            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            string backup = dbPath + ".bak-" + stamp;
            File.Copy(dbPath, backup, false);

            IntPtr db = IntPtr.Zero;
            try
            {
                db = Open(dbPath, sqliteDll);
                Exec(db, "BEGIN IMMEDIATE");
                string escapedHash = EscapeSql(exeHash);
                string escapedMarker = EscapeSql(AdapterCore.ToolMarker);
                Exec(db, "DELETE FROM game_version WHERE description LIKE '" + escapedMarker + "%' AND UPPER(sha256_hash) <> '" + escapedHash + "'");
                List<string[]> exists = Query(db, "SELECT sha256_hash FROM game_version WHERE UPPER(sha256_hash)='" + escapedHash + "' LIMIT 1", 1);
                if (exists.Count == 0)
                {
                    string desc = EscapeSql(AdapterCore.ToolMarker + " current executable " + exeHash);
                    Exec(db,
                        "INSERT INTO game_version (id, sha256_hash, game_name, version_string, description, platform) " +
                        "VALUES ((SELECT COALESCE(MAX(id),0)+1 FROM game_version), '" + escapedHash + "', 'KOTOR1', 'custom adapted 1.03', '" + desc + "', 'Windows')");
                }
                List<string[]> check = Query(db, "PRAGMA integrity_check", 1);
                string integrity = check.Count > 0 ? check[0][0] : "no result";
                if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
                    throw new AdapterException("SQLite integrity_check failed after update: " + integrity);
                Exec(db, "COMMIT");
                sqlite3_close(db);
                db = IntPtr.Zero;

                DbAnalysis after = Analyze(dbPath, sqliteDll, exeHash);
                if (!after.Valid || !after.HasHash) throw new AdapterException("Database verification failed after update.");
                return backup;
            }
            catch
            {
                if (db != IntPtr.Zero)
                {
                    try { Exec(db, "ROLLBACK"); } catch { }
                    try { sqlite3_close(db); } catch { }
                }
                try { File.Copy(backup, dbPath, true); } catch { }
                throw;
            }
        }
    }
}
