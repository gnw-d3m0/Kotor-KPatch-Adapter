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
    internal sealed class MainForm : Form
    {
        private TextBox exeBox;
        private TextBox managerBox;
        private ListBox patchList;
        private RichTextBox output;
        private Button analyzeButton;
        private Button convertButton;
        private Label statusLabel;

        private ExeAnalysis lastExe;
        private List<PatchAnalysis> lastAnalyses = new List<PatchAnalysis>();
        private DbAnalysis lastDb;

        public MainForm()
        {
            Text = "KOTOR KPatch Adapter " + AdapterCore.Version;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(850, 650);
            Size = new Size(1000, 760);
            Font = new Font("Segoe UI", 9F);
            BuildUi();
        }

        private void BuildUi()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(12);
            root.ColumnCount = 1;
            root.RowCount = 6;
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 145));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            Label intro = new Label();
            intro.AutoSize = true;
            intro.MaximumSize = new Size(940, 0);
            intro.Text = "Select your current swkotor.exe, your Kotor Patch Manager folder, and one or more .kpatch files. The adapter verifies every hook's original bytes before allowing conversion. It never modifies swkotor.exe.";
            root.Controls.Add(intro, 0, 0);

            TableLayoutPanel paths = new TableLayoutPanel();
            paths.Dock = DockStyle.Top;
            paths.AutoSize = true;
            paths.ColumnCount = 3;
            paths.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 155));
            paths.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            paths.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 85));
            root.Controls.Add(paths, 0, 1);

            paths.Controls.Add(MakeLabel("swkotor.exe"), 0, 0);
            exeBox = new TextBox(); exeBox.Dock = DockStyle.Fill;
            paths.Controls.Add(exeBox, 1, 0);
            Button exeBrowse = new Button(); exeBrowse.Text = "Browse..."; exeBrowse.AutoSize = true; exeBrowse.Click += BrowseExe;
            paths.Controls.Add(exeBrowse, 2, 0);

            paths.Controls.Add(MakeLabel("Patch Manager folder"), 0, 1);
            managerBox = new TextBox(); managerBox.Dock = DockStyle.Fill;
            paths.Controls.Add(managerBox, 1, 1);
            Button mgrBrowse = new Button(); mgrBrowse.Text = "Browse..."; mgrBrowse.AutoSize = true; mgrBrowse.Click += BrowseManager;
            paths.Controls.Add(mgrBrowse, 2, 1);

            GroupBox patchGroup = new GroupBox();
            patchGroup.Text = ".kpatch files";
            patchGroup.Dock = DockStyle.Fill;
            root.Controls.Add(patchGroup, 0, 2);
            TableLayoutPanel patchLayout = new TableLayoutPanel();
            patchLayout.Dock = DockStyle.Fill;
            patchLayout.ColumnCount = 2;
            patchLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            patchLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            patchGroup.Controls.Add(patchLayout);
            patchList = new ListBox(); patchList.Dock = DockStyle.Fill; patchList.SelectionMode = SelectionMode.MultiExtended;
            patchLayout.Controls.Add(patchList, 0, 0);
            FlowLayoutPanel patchButtons = new FlowLayoutPanel();
            patchButtons.FlowDirection = FlowDirection.TopDown; patchButtons.Dock = DockStyle.Fill;
            Button add = new Button(); add.Text = "Add..."; add.Width = 85; add.Click += AddPatches;
            Button remove = new Button(); remove.Text = "Remove"; remove.Width = 85; remove.Click += RemovePatches;
            Button clear = new Button(); clear.Text = "Clear"; clear.Width = 85; clear.Click += delegate { patchList.Items.Clear(); ResetAnalysis(); };
            patchButtons.Controls.Add(add); patchButtons.Controls.Add(remove); patchButtons.Controls.Add(clear);
            patchLayout.Controls.Add(patchButtons, 1, 0);

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.AutoSize = true; actions.Dock = DockStyle.Fill;
            analyzeButton = new Button(); analyzeButton.Text = "Analyze Compatibility"; analyzeButton.AutoSize = true; analyzeButton.Padding = new Padding(8, 4, 8, 4); analyzeButton.Click += AnalyzeClicked;
            convertButton = new Button(); convertButton.Text = "Convert & Update Patch Manager"; convertButton.AutoSize = true; convertButton.Padding = new Padding(8, 4, 8, 4); convertButton.Enabled = false; convertButton.Click += ConvertClicked;
            actions.Controls.Add(analyzeButton); actions.Controls.Add(convertButton);
            root.Controls.Add(actions, 0, 3);

            statusLabel = new Label(); statusLabel.AutoSize = true; statusLabel.Text = "Ready."; statusLabel.Padding = new Padding(0, 4, 0, 4);
            root.Controls.Add(statusLabel, 0, 4);

            output = new RichTextBox();
            output.Dock = DockStyle.Fill;
            output.ReadOnly = true;
            output.Font = new Font("Consolas", 9F);
            output.WordWrap = false;
            output.BackColor = SystemColors.Window;
            root.Controls.Add(output, 0, 5);
        }

        private static Label MakeLabel(string text)
        {
            Label l = new Label(); l.Text = text; l.AutoSize = true; l.Anchor = AnchorStyles.Left; l.Padding = new Padding(0, 6, 0, 0); return l;
        }

        private void BrowseExe(object sender, EventArgs e)
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Filter = "KOTOR executable (swkotor.exe)|swkotor*.exe|Executable files (*.exe)|*.exe|All files (*.*)|*.*";
                d.Title = "Select your current swkotor.exe";
                if (d.ShowDialog(this) == DialogResult.OK) { exeBox.Text = d.FileName; ResetAnalysis(); }
            }
        }

        private void BrowseManager(object sender, EventArgs e)
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog())
            {
                d.Description = "Select the Kotor Patch Manager folder (the folder containing sqlite3.dll).";
                if (d.ShowDialog(this) == DialogResult.OK) { managerBox.Text = d.SelectedPath; ResetAnalysis(); }
            }
        }

        private void AddPatches(object sender, EventArgs e)
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Filter = "Kotor Patch Manager patches (*.kpatch)|*.kpatch|All files (*.*)|*.*";
                d.Multiselect = true;
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    foreach (string p in d.FileNames)
                    {
                        bool duplicate = false;
                        foreach (PatchListItem item in patchList.Items)
                            if (string.Equals(item.Path, p, StringComparison.OrdinalIgnoreCase)) duplicate = true;
                        if (!duplicate) patchList.Items.Add(new PatchListItem { Path = p });
                    }
                    ResetAnalysis();
                }
            }
        }

        private void RemovePatches(object sender, EventArgs e)
        {
            List<object> selected = patchList.SelectedItems.Cast<object>().ToList();
            foreach (object item in selected) patchList.Items.Remove(item);
            ResetAnalysis();
        }

        private void ResetAnalysis()
        {
            lastExe = null;
            lastAnalyses.Clear();
            lastDb = null;
            convertButton.Enabled = false;
            statusLabel.Text = "Selections changed. Analyze again.";
        }

        private string DbPath
        {
            get { return System.IO.Path.Combine(managerBox.Text.Trim(), "bin", "AddressDatabases", "kotor1_0_3.db"); }
        }

        private string SqlitePath
        {
            get { return System.IO.Path.Combine(managerBox.Text.Trim(), "sqlite3.dll"); }
        }

        private bool ValidateInputs()
        {
            if (!File.Exists(exeBox.Text.Trim())) { MessageBox.Show(this, "Select a valid swkotor.exe.", "Missing EXE", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            if (!Directory.Exists(managerBox.Text.Trim())) { MessageBox.Show(this, "Select a valid Kotor Patch Manager folder.", "Missing Patch Manager", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            if (!File.Exists(DbPath)) { MessageBox.Show(this, "Could not find:\r\n" + DbPath, "Missing address database", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            if (!File.Exists(SqlitePath)) { MessageBox.Show(this, "Could not find:\r\n" + SqlitePath, "Missing sqlite3.dll", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            if (patchList.Items.Count == 0) { MessageBox.Show(this, "Add at least one .kpatch file.", "No patches", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            return true;
        }

        private void AnalyzeClicked(object sender, EventArgs e)
        {
            if (!ValidateInputs()) return;
            Cursor = Cursors.WaitCursor;
            analyzeButton.Enabled = false;
            convertButton.Enabled = false;
            statusLabel.Text = "Analyzing...";
            Application.DoEvents();
            try
            {
                lastExe = AdapterCore.AnalyzeExe(exeBox.Text.Trim());
                lastAnalyses = new List<PatchAnalysis>();
                foreach (PatchListItem item in patchList.Items)
                    lastAnalyses.Add(AdapterCore.AnalyzePatch(item.Path, lastExe));
                lastDb = SqliteNative.Analyze(DbPath, SqlitePath, lastExe.Sha256);
                output.Text = AdapterCore.FormatAnalysis(lastExe, lastAnalyses, lastDb);

                List<string> overlaps = AdapterCore.DetectHookOverlaps(lastAnalyses);
                bool allGood = lastAnalyses.Count > 0 && lastAnalyses.All(x => x.Compatible) && lastDb.Valid && overlaps.Count == 0;
                convertButton.Enabled = allGood;
                statusLabel.Text = allGood ? "Compatible. Conversion is available." : "Conversion blocked. Review the analysis below.";
            }
            catch (Exception ex)
            {
                output.Text = ex.ToString();
                statusLabel.Text = "Analysis failed.";
                MessageBox.Show(this, ex.Message, "Analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                analyzeButton.Enabled = true;
                Cursor = Cursors.Default;
            }
        }

        private void ConvertClicked(object sender, EventArgs e)
        {
            if (lastExe == null || lastAnalyses.Count == 0 || lastDb == null || !lastDb.Valid || !lastAnalyses.All(x => x.Compatible))
            {
                MessageBox.Show(this, "Run a successful compatibility analysis first.", "Analyze first", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (AdapterCore.DetectHookOverlaps(lastAnalyses).Count > 0)
            {
                MessageBox.Show(this, "Selected patches contain overlapping hooks. Automatic conversion is disabled.", "Hook overlap", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string msg = "The adapter will:\r\n\r\n" +
                         "- create adapted copies of the selected .kpatch files\r\n" +
                         "- back up kotor1_0_3.db\r\n" +
                         "- update the existing database in place for this exact EXE hash\r\n\r\n" +
                         "It will NOT modify swkotor.exe.\r\n\r\nContinue?";
            if (MessageBox.Show(this, msg, "Convert patches", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            Cursor = Cursors.WaitCursor;
            analyzeButton.Enabled = false;
            convertButton.Enabled = false;
            statusLabel.Text = "Converting...";
            Application.DoEvents();
            List<string> created = new List<string>();
            try
            {
                foreach (PatchAnalysis a in lastAnalyses) created.Add(AdapterCore.ConvertPatch(a, lastExe));
                string backup = SqliteNative.UpdateInPlace(DbPath, SqlitePath, lastExe.Sha256);

                StringBuilder sb = new StringBuilder(output.Text);
                sb.AppendLine();
                sb.AppendLine("CONVERSION COMPLETE");
                foreach (string p in created) sb.AppendLine("  Created: " + p);
                sb.AppendLine("  Updated: " + DbPath);
                sb.AppendLine("  Database backup: " + backup);
                sb.AppendLine("  swkotor.exe was not modified.");
                output.Text = sb.ToString();
                statusLabel.Text = "Conversion completed successfully.";
                MessageBox.Show(this, "Converted patches were created and the Patch Manager database was updated successfully.", "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                foreach (string p in created) { try { if (File.Exists(p)) File.Delete(p); } catch { } }
                statusLabel.Text = "Conversion failed.";
                MessageBox.Show(this, ex.Message, "Conversion failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                analyzeButton.Enabled = true;
                Cursor = Cursors.Default;
            }
        }
    }
}
