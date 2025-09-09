namespace HD2_TS_Tool
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.sysinfo = new System.Windows.Forms.Button();
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.genchecks = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.setdns = new System.Windows.Forms.Button();
            this.wipeshaders = new System.Windows.Forms.Button();
            this.wipeappdata = new System.Windows.Forms.Button();
            this.readdumps = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.moreopts = new System.Windows.Forms.Panel();
            this.wipemods = new System.Windows.Forms.Button();
            this.netchecks = new System.Windows.Forms.Button();
            this.progressBar1 = new System.Windows.Forms.ProgressBar();
            this.progPanel = new System.Windows.Forms.Panel();
            this.progressLabel = new System.Windows.Forms.Label();
            this.wipeadapter = new System.Windows.Forms.Button();
            this.moreopts.SuspendLayout();
            this.progPanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // sysinfo
            // 
            this.sysinfo.Location = new System.Drawing.Point(15, 6);
            this.sysinfo.Name = "sysinfo";
            this.sysinfo.Size = new System.Drawing.Size(159, 29);
            this.sysinfo.TabIndex = 0;
            this.sysinfo.Text = "System Info";
            this.sysinfo.UseVisualStyleBackColor = true;
            this.sysinfo.Click += new System.EventHandler(this.sysinfo_Click);
            // 
            // richTextBox1
            // 
            this.richTextBox1.Location = new System.Drawing.Point(219, 12);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(969, 682);
            this.richTextBox1.TabIndex = 1;
            this.richTextBox1.Text = resources.GetString("richTextBox1.Text");
            // 
            // genchecks
            // 
            this.genchecks.Location = new System.Drawing.Point(15, 76);
            this.genchecks.Name = "genchecks";
            this.genchecks.Size = new System.Drawing.Size(159, 29);
            this.genchecks.TabIndex = 2;
            this.genchecks.Text = "General Checks";
            this.genchecks.UseVisualStyleBackColor = true;
            this.genchecks.Click += new System.EventHandler(this.genchecks_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 222);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(99, 16);
            this.label1.TabIndex = 3;
            this.label1.Text = "One Click Fixes";
            // 
            // setdns
            // 
            this.setdns.Location = new System.Drawing.Point(15, 241);
            this.setdns.Name = "setdns";
            this.setdns.Size = new System.Drawing.Size(159, 29);
            this.setdns.TabIndex = 4;
            this.setdns.Text = "Set DNS";
            this.setdns.UseVisualStyleBackColor = true;
            this.setdns.Click += new System.EventHandler(this.setdns_Click);
            // 
            // wipeshaders
            // 
            this.wipeshaders.Location = new System.Drawing.Point(3, 3);
            this.wipeshaders.Name = "wipeshaders";
            this.wipeshaders.Size = new System.Drawing.Size(159, 29);
            this.wipeshaders.TabIndex = 5;
            this.wipeshaders.Text = "Clear Shaders";
            this.wipeshaders.UseVisualStyleBackColor = true;
            this.wipeshaders.Click += new System.EventHandler(this.wipeshaders_Click);
            // 
            // wipeappdata
            // 
            this.wipeappdata.Location = new System.Drawing.Point(3, 38);
            this.wipeappdata.Name = "wipeappdata";
            this.wipeappdata.Size = new System.Drawing.Size(159, 29);
            this.wipeappdata.TabIndex = 6;
            this.wipeappdata.Text = "Wipe HD2 AppData";
            this.wipeappdata.UseVisualStyleBackColor = true;
            this.wipeappdata.Click += new System.EventHandler(this.wipeappdata_Click);
            // 
            // readdumps
            // 
            this.readdumps.Location = new System.Drawing.Point(15, 41);
            this.readdumps.Name = "readdumps";
            this.readdumps.Size = new System.Drawing.Size(159, 29);
            this.readdumps.TabIndex = 7;
            this.readdumps.Text = "Read Latest Dump";
            this.readdumps.UseVisualStyleBackColor = true;
            this.readdumps.Click += new System.EventHandler(this.readdumps_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 413);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(168, 32);
            this.label2.TabIndex = 8;
            this.label2.Text = "More One Click Fixes\r\nRun \"General Checks\" First";
            // 
            // moreopts
            // 
            this.moreopts.Controls.Add(this.wipemods);
            this.moreopts.Controls.Add(this.wipeshaders);
            this.moreopts.Controls.Add(this.wipeappdata);
            this.moreopts.Location = new System.Drawing.Point(15, 448);
            this.moreopts.Name = "moreopts";
            this.moreopts.Size = new System.Drawing.Size(166, 218);
            this.moreopts.TabIndex = 9;
            this.moreopts.Visible = false;
            // 
            // wipemods
            // 
            this.wipemods.Location = new System.Drawing.Point(3, 73);
            this.wipemods.Name = "wipemods";
            this.wipemods.Size = new System.Drawing.Size(159, 29);
            this.wipemods.TabIndex = 7;
            this.wipemods.Text = "Remove Mods";
            this.wipemods.UseVisualStyleBackColor = true;
            this.wipemods.Click += new System.EventHandler(this.wipemods_Click);
            // 
            // netchecks
            // 
            this.netchecks.Location = new System.Drawing.Point(15, 111);
            this.netchecks.Name = "netchecks";
            this.netchecks.Size = new System.Drawing.Size(159, 29);
            this.netchecks.TabIndex = 10;
            this.netchecks.Text = "Network Checks";
            this.netchecks.UseVisualStyleBackColor = true;
            this.netchecks.Click += new System.EventHandler(this.netchecks_Click);
            // 
            // progressBar1
            // 
            this.progressBar1.Location = new System.Drawing.Point(0, 42);
            this.progressBar1.Name = "progressBar1";
            this.progressBar1.Size = new System.Drawing.Size(410, 25);
            this.progressBar1.TabIndex = 11;
            // 
            // progPanel
            // 
            this.progPanel.Controls.Add(this.progressLabel);
            this.progPanel.Controls.Add(this.progressBar1);
            this.progPanel.Location = new System.Drawing.Point(489, 312);
            this.progPanel.Name = "progPanel";
            this.progPanel.Size = new System.Drawing.Size(410, 70);
            this.progPanel.TabIndex = 12;
            this.progPanel.Visible = false;
            // 
            // progressLabel
            // 
            this.progressLabel.AutoSize = true;
            this.progressLabel.Location = new System.Drawing.Point(3, 9);
            this.progressLabel.Name = "progressLabel";
            this.progressLabel.Size = new System.Drawing.Size(26, 16);
            this.progressLabel.TabIndex = 12;
            this.progressLabel.Text = "NA";
            // 
            // wipeadapter
            // 
            this.wipeadapter.Location = new System.Drawing.Point(15, 276);
            this.wipeadapter.Name = "wipeadapter";
            this.wipeadapter.Size = new System.Drawing.Size(159, 29);
            this.wipeadapter.TabIndex = 13;
            this.wipeadapter.Text = "Reset Network Adapter";
            this.wipeadapter.UseVisualStyleBackColor = true;
            this.wipeadapter.Click += new System.EventHandler(this.wipeadapter_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1200, 706);
            this.Controls.Add(this.wipeadapter);
            this.Controls.Add(this.progPanel);
            this.Controls.Add(this.netchecks);
            this.Controls.Add(this.moreopts);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.readdumps);
            this.Controls.Add(this.setdns);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.genchecks);
            this.Controls.Add(this.richTextBox1);
            this.Controls.Add(this.sysinfo);
            this.Name = "Form1";
            this.Text = "HD2-TS-Tool";
            this.moreopts.ResumeLayout(false);
            this.progPanel.ResumeLayout(false);
            this.progPanel.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button sysinfo;
        private System.Windows.Forms.RichTextBox richTextBox1;
        private System.Windows.Forms.Button genchecks;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button setdns;
        private System.Windows.Forms.Button wipeshaders;
        private System.Windows.Forms.Button wipeappdata;
        private System.Windows.Forms.Button readdumps;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Panel moreopts;
        private System.Windows.Forms.Button netchecks;
        private System.Windows.Forms.ProgressBar progressBar1;
        private System.Windows.Forms.Panel progPanel;
        private System.Windows.Forms.Label progressLabel;
        private System.Windows.Forms.Button wipeadapter;
        private System.Windows.Forms.Button wipemods;
    }
}

