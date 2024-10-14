# Copyright (C) 2015 KillerInstinct, Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Creates a known ransomware decryption instruction / key file."
    weight = 3
    severity = 3
    families = []
    categories = ["ransomware"]
    authors = ["KillerInstinct", "bartblaze"]
    minimum = "1.2"
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]
    mbcs += ["OC0001", "C0016", "C0016.002"]  # micro-behaviour

    def run(self):
        # List of tuples with a regex pattern for the file name and a list of
        # family names correlating to the ransomware. If the family is unknown
        # just use [""].
        file_list = (
            (r".*\\help_decrypt\.html$", ["CryptoWall"]),
            (r".*\\decrypt_instruction\.html$", ["CryptoWall"]),
            (r".*\\help_your_files\.png$", ["CryptoWall"]),
            (r".*\\decrypt_instructions\.txt$", ["CryptoLocker"]),
            (r".*\\vault\.(key|txt)$", ["CrypVault"]),
            (r".*\\!Decrypt-All-Files.*\.(txt|bmp)$", ["CTB-Locker"]),
            (r".*\\help_restore_files\.txt$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\help_to_save_files\.(txt|bmp)$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\recovery_(file|key)\.txt$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\restore_files_.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\howto_restore_files.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\+-xxx-HELP-xxx-+.*\.(png|txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\HELP_RECOVER_instructions\+.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            # r (".*\\YOUR_FILES_ARE_ENCRYPTED\.HTML$", ["Chimera"]),
            (r".*\\_?how_recover.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (r".*\\cl_data.*\.bak$", ["WinPlock"]),
            (r".*\\READ\ ME\ FOR\ DECRYPT\.txt$", ["Fakben"]),
            (r".*\\YOUR_FILES.url$", ["Radamant"]),
            (r".*\\_How\ to\ decrypt\ LeChiffre\ files\.html$", ["LeChiffre"]),
            (r".*\\cryptinfo\.txt$", ["DMALocker"]),
            (r".*\\README_DECRYPT_HYDRA_ID_.*(\.txt|\.jpg)$", ["HydraCrypt"]),
            (r".*\\_Locky_recover_instructions\.txt$", ["Locky"]),
            (r".*\\_DECRYPT_INFO_[a-z]{4,6}\.html$", ["Maktub"]),
            (r".*\\de_crypt_readme\.(html|txt|bmp)$", ["CryptXXX"]),
            (r".*\\HELP_YOUR_FILES\.(html|txt)$", ["CryptFile2"]),
            (r".*\\READ_IT\.txt$", ["MMLocker"]),
            (r".*\\#\ DECRYPT\ MY\ FILES\ #\.(txt|html|vbs)$", ["Cerber"]),
            (r".*\\!satana!\.txt$", ["Satana"]),
            (r".*\\HOW_TO_UNLOCK_FILES_README_\([0-9a-f]+\)\.(txt|html|bmp)$", ["WildFire"]),
            (r".*\\HELP_DECRYPT_YOUR_FILES\.(html|txt)$", ["CryptFile2"]),
            (r".*\\!!!\ Readme\ For\ Decrypt\ !!!\.txt$", ["MarsJoke"]),
            (r".*_HOWDO_text\.(html|bmp)$", ["Locky"]),
            (r".*\\!!_RECOVERY_instructions_!!\.(html|txt)$", ["Nuke"]),
            (r".*\\DECRYPT_YOUR_FILES\.HTML$", ["Fantom"]),
            (r".*\\README_RECOVER_FILES_.*\.(html|txt|png)$", ["HadesLocker"]),
            (r".*\\README\.hta$", ["Cerber"]),
            (r".*\\RESTORE-FILES!.*txt$", ["Comrade-Circle"]),
            (r".*_WHAT_is\.(html|bmp)$", ["Locky"]),
            (r".*\\decrypt\ explanations\.html$", ["n1n1n1"]),
            (r".*\\ransomed\.html$", ["Alcatraz-Locker"]),
            (r".*\\CHIP_FILES\.txt$", ["CHIP"]),
            (r".*\\(?:|_\d\-|\-)INSTRUCTION\.(html|bmp)$", ["Locky"]),
            (r".*\\_README(\.hta|_.*_\.hta)$", ["Cerber"]),
            (r".*\\DesktopOSIRIS\.(bmp|htm)$", ["Locky"]),
            (r".*\\OSIRIS\-[a-f0-9]{4}\.htm$", ["Locky"]),
            (r"C:\\[a-z]{8}\.tsv$", ["MegaCortex"]),
            (r"C:\\!!!_READ_ME_!!!.txt$", ["MegaCortex"]),
            (r".*\\README_LOCKED\.txt$", ["LockerGoga"]),
            (r".*\\README-NOW.txt\.txt$", ["LockerGoga"]),
            (r".*\\!-GET_MY_FILES-!\.txt$", ["Aurora", "Zorro"]),
            (r".*\\#RECOVERY-PC#\.txt$", ["Aurora", "Zorro"]),
            (r".*\\@_RESTORE-FILES_@\.txt$", ["Aurora", "Zorro"]),
            (r".*\\HOW_TO_DECRYPT\.txt$", ["BasilisqueLocker"]),
            (r".*\\!!!\ YOUR\ FILES\ ARE\ ENCRYPTED\ !!!\.TXT$", ["Buran"]),
            (r".*\\!!!CHEKYSHKA_DECRYPT_README\.TXT$", ["Chekyshka"]),
            (r".*\\HOW_TO_BACK_YOUR_FILES\.txt$", ["ChineseRarypt"]),
            (r".*\\CIopReadMe\.txt$", ["Clop-CryptoMix"]),
            (r".*\\_HELP_INSTRUCTION\.TXT$", ["CryptoMix"]),
            (r".*\\!=How_recovery_files=!\.html$", ["Everbe"]),
            (r".*\\\.FreezedByMagic\.README\.txt$", ["FreeMe"]),
            (r"C:\\ProgramData\\\.FreezedByMagic.LOG$", ["FreeMe"]),
            (r".*\\#\ DECRYPT\ MY\ FILES\ #\.txt$", ["GetCrypt"]),
            (r".*\\RECOVER-FILES\.html$", ["GlobeImposter"]),
            (r".*\\READ_IT\.html$", ["GlobeImposter"]),
            (r".*\\Read___ME\.html$", ["GlobeImposter"]),
            (r".*\\how_to_back_files\.html$", ["GlobeImposter"]),
            (r".*\\How\ to\ restore\ your\ files\.hta$", ["GlobeImposter"]),
            (r".*\\#NEW_WAVE\.html$", ["GlobeImposter"]),
            (r".*\\YOU_FILES_HERE\.html$", ["GlobeImposter"]),
            (r".*\\#\ instructions-[A-Z0-9]{5}\ #\.(txt|jpg|vbs)$", ["GoldenAxe"]),
            (r".*\\README_DECRYPT\.txt$", ["Gpgqwerty"]),
            (r".*\\DECRYPT_INFORMATION\.html$", ["Hermes"]),
            (r".*\\precist\.html$", ["JoeGo"]),
            (r".*\\JSWORM-DECRYPT\.(hta|html)$", ["JSWorm"]),
            (r".*\\READ-ME-NOW\.txt$", ["LockerGoga"]),
            (r".*\\@Please_Read_Me\.txt$", ["LooCipher"]),
            (r".*\\!INSTRUCTI0NS!\.TXT$", ["Maoloa"]),
            (r".*\\DECRYPT-FILES\.(html|txt)$", ["Maze"]),
            (r".*\\help\ to\ decrypt\.html$", ["MorrisBatchCrypt"]),
            (r".*\\_Decrypt_Files\.html$", ["Robbinhood"]),
            (r".*\\_Help_Help_Help\.html$", ["Robbinhood"]),
            (r".*\\_Help_Important\.html$", ["Robbinhood"]),
            (r".*\\_Decryption_ReadMe\.html$", ["Robbinhood"]),
            (r".*\\RyukReadMe\.txt$", ["Ryuk"]),
            (r"C:\\[a-z0-9]{6,9}-HOW-TO-DECRYPT\.txt$", ["Sodinokibi", "REvil"]),
            (r"C:\\[a-z0-9]{6,9}-readme\.txt$", ["Sodinokibi", "REvil"]),
            (r".*\\#NEWRAR_README#\.TXT$", ["VSSDestroy"]),
            (r".*\\#DECRYPT_MY_FILES#\.txt$", ["Aurora", "Zorro", "Dragon"]),
            (r".*\\@\ READ\ ME\ TO\ RECOVER\ FILES\ @\.txt", ["Eris"]),
            (r".*\\[A-Z0-9]{4,9}-MANUAL\.txt", ["GandCrab"]),
            (r".*\\NEMTY-DECRYPT\.txt$", ["Nemty"]),
            (r".*\\README-VIAGRA-[A-Za-z0-9]{8}\.HTML$", ["Viagra"]),
            (r".*\\PLAGUE[0-9]{2}\.txt$", ["Plague"]),
            (r".*\\READ\ ME\.(hta|TXT)$", ["Scarab-Dharma"]),
            (r".*\\FIX_Instructions\.(txt|hta)$", ["Relock"]),
            (r".*\\Readme_now\.txt$", ["Syrk"]),
            (r".*\\!_Notice_!\.txt$", ["TFlower"]),
            (r".*\\@Please_Read_Me@\.txt$", ["WannaCry"]),
            (r".*\\_readme\.txt$", ["STOP-Djvu"]),
            (r".*\\#FOX_README#\.rtf$", ["Fox"]),
            (r".*\\Restore-My-Files\.txt$", ["LockBit"]),
            (r".*\\HOW_DECRYPT_FILES\.txt$", ["Estemani"]),
            (r".*\\[A-Z0-9]{6}-Readme\.txt$", ["Koko", "Mailto"]),
            (r".*\\#README\.lilocked$", ["Lilocked"]),
            (r".*\\SGUARD-README\.(txt|TXT)$", ["SGuard"]),
            (r".*\\RyukReadMe\.html$", ["Ryuk"]),
            (r".*\\HOW_TO_RECOVER_DATA\.html$", ["MedusaLocker"]),
            (r".*\\ClopReadMe\.txt$", ["Clop-CryptoMix"]),
            (r".*\\Fix-Your-Files\.txt$", ["SNAKE"]),
            (r".*\\__________WHY FILES NOT WORK__________\.txt$", ["Hydra"]),
            (r".*\\.readme2unlock\.txt$", ["DoppelPaymer"]),
            (r".*\\How_To_Decrypt_My_Files\.txt$", ["Ragnarok"]),
            (r".*\\RGNR_[A-Z0-9]{8}\.txt$", ["RagnarLocker"]),
            (r".*\\H0w_T0_Rec0very_Files\.txt$", ["PwndLocker"]),
            (r".*\\\[HOW TO RECOVER FILES\]\.txt$", ["ProLock"]),
            (r".*\\CONTI_README\.txt$", ["Conti"]),
            (r".*\\!*_read_me!\.txt$", ["RansomEXX"]),
            (r".*\\!\$R4GN4R_[A-Z0-9]{8}\$!\.txt$", ["RagnarLocker"]),
            (r".*\\[0-9]{6}-readme.html$", ["Avaddon"]),
            (r".*\\[A-Za-z]{6}_readme.txt$", ["Avaddon"]),
            (r".*\\[A-Z0-9]{6}-Readme.txt$", ["NetWalker"]),
            (r".*\\[a-z]{5}_readme.txt$", ["Avaddon"]),
            (r".*\\conti\.txt$", ["Conti"]),
            (r".*\\!!_FILES_ENCRYPTED_\.txt$", ["Sfile-Escal"]),
            (r".*\\payment request\.(txt|html)$", ["Jackpot"]),
            (r".*\\r3adm3\.txt$", ["ContiV2"]),
            (r".*\\HACKED\.txt$", ["Smaug"]),
            (r".*\\YOUR_FILES_ARE_ENCRYPTED\.HTML$", ["SunCrypt"]),
            (r".*\\RecoveryManual\.html$", ["MountLocker"]),
            (r".*\\Readme\.README$", ["PYSA"]),
            (r".*\\How\sTo\sRestore\sYour\sFiles\.txt$", ["Babuk"]),
            (r".*\\PHOENIX-HELP\.txt", ["PhoenixCryptoLocker"]),
            (r".*\\BlackByte_restoremyfiles.txt", ["BlackByte"]),
        )

        for ioc in file_list:
            if self.check_write_file(pattern=ioc[0], regex=True):
                if ioc[1] != "":
                    self.families = ioc[1]
                    self.description = (
                        "Creates a known {0} ransomware " "decryption instruction / key file." "".format("/".join(ioc[1]))
                    )
                return True

        return False
