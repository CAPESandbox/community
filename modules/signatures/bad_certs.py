# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class BadCerts(Signature):
    name = "bad_certs"
    description = "The executable used a known stolen/malicious Authenticode signature"
    severity = 3
    weight = 4
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        md5_indicators = []
        sha1_indicators = [
            # Buhtrap from http://www.welivesecurity.com/2015/04/09/operation-buhtrap/
            "cf5a43d14c6ad0c7fdbcbe632ab7c789e39443ee",
            "e9af1f9af597a9330c52a7686bf70b0094ad7616",
            "3e1a6e52a1756017dd8f03ff85ec353273b20c66",
            "efad94fc87b2b3a652f1a98901204ea8fbeef474",
            # Stolen Sony cert
            "8df46b5fdac2eb3b4757f99866c199ff2b13427a",
            # Stolen Bit9 cert
            "555d2d20851e849f0c109e243cf8a5da1f9995d7",
            # Sysprint AG cert used in Turla
            "24215864f128972b2622172dee6282460799ca46",
            # Stolen Source Medical Solutions cert
            "b501aab2ffc3bddb7e847c4acee4be41de38f16e",
            # Adobe stolen cert
            "fdf01dd3f37c66ac4c779d92623c77814a07fe4c",
            # used in a Dridex sample: KASHTAN OOO
            "401909e89a0e59335b624e147719f0b88d51705a",
            # used in a Punkey sample: MOGLIANI & SON LIMITED
            "c5d386f697777643751ec33b6b689eef71791293",
            # used in Duqu2: HON HAI PRECISION INDUSTRY CO. LTD.
            "c7938dd4bec741574683b4f3dd54717f98e54c90",
            # HackingTeam Dump
            "2e8734348c03390d24faf96e86bb01b39e3ad4db",
            "b7c646e3a433986e165ba45b209da4a2c4111939",
            "fdc9281ab92d4fb85a03254dcb62d1c29a803fb1",
            "2a1da6dc8635e6c725cccbe6c035eec813fbeb2e",
            # Wild Neutron (Stolen Acer Incorporated cert)
            "0d859141ee9a0c6e725ffe6bcfc99f3efcc3fc07",
            # Used in Dridex, BIZNES AVTOMATYKA
            "9a9c618cc8f50e9ffb24b6cc8b34858fa65e778c",
            # Stolen ThreatTrack cert
            "8138b44330354e413dc52af1dbfca8ba1c0f6c0a",
            # eDellRoot Signed File http://en.community.dell.com/dell-blogs/direct2dell/b/direct2dell/archive/2015/11/23/response-to-concerns-regarding-edellroot-certificate
            "98a04e4163357790c4a79e6d713ff0af51fe6927",
            # Spymel Cert (SBO INVEST)
            "3a8412582563f43dd28aa1f31cdd0d0c6d78fd60",
            # DIDZHITAL ART cert used for Kovter
            "a286affc5f6e92bdc93374646676ebc49e21bcae",
            # Tiks IT cert used for Kovter
            "78d98ccccc41e0dea1791d24595c2e90f796fd48",
            # VB CORPORATE PTY. LTD.
            "23250aa8e1b8ae49a64d09644db3a9a65f866957",
            # James LTH d.o.o.
            "1bb5503a2e1043616b915c4fce156c34304505d6",
            # OOO MEP
            "8c762918a58ebccb1713720c405088743c0d6d20",
            # RESURS-RM OOO
            "1174c2affb0a364c1b7a231168cfdda5989c04c5",
            # Logika OOO
            "92AC76277EF2B1FC8D91AD81C472059891484C2C",
            # Rov SP Z O O
            "dafd9d27e86daf31f9e9a9f467090eca65c0d2e3",
            # Maxiol
            "95cb954d37a261f4c5d3479567b50bd7725908ee",
            # Nordkod LLC
            "2052ed19dcb0e3dfff71d217be27fc5a11c0f0d4",
            # Retalit LLC
            "52fe4ecd6c925e89068fee38f1b9a669a70f8bab",
            # NEEDCODE SP Z O O,
            "c3288c7fbb01214c8f2dc3172c3f5c48f300cb8b",
            # KLAKSON, LLC
            "a9eb61783fabe97aa1040103430eb8269d443b0a",
            # VESNA, OOO
            "64197ff3b465b9d3c9300eb985ce635ee1c3dd6a",
            # Tramplink LLC
            "36d4070f0a92d54e8915f122822602fee3114fb3",
            # Milsean Software Limited
            "552eabcaf5b6d26bcd9d584346701c45c3fda18c",
            # Carmel group LLC
            "4d127ce781a74af7aab1373a5af2625ffb27e2fa",
            # Master Networking s.r.o.
            "2dbbbedc7fd628132660c05ef3d1147e1194d8dd",
            # DocsGen Software Solutions Inc.
            "c4b81197fac9129d0d1d65fe14fdac7f2008bff6",
            # Lets Start SP Z O O
            "2e23856699c852d258bf61edf507c3362ae83be3",
            # Elite Web Development Ltd.
            "ad300c8d9631f68dc220f7ef3addd40aee86869e",
            # Digital Capital Management Ireland Limited
            "be030fefb88f9cfd0b67be014662ae419e4936c0",
            # PARTS-JEST d.o.o.
            "21771e4b8ba6e232aefe93f6a4c28c6964eb0f10",
            # Equal Cash Technologies Limited
            "345c2a6a717273e365f9302bc52ce065c50518e6",
            # Data Analytics Services Consulting Pte. Ltd.
            "d45754f098ed3bd60b65955b1093f1d4a73bb60f",
            # Korist Networks Incorporated
            "1d2f7867dccac28a856cf884e4db54e7a99d1382",
            # MEHANIKUM OOO
            "b0c4bc601aa0b8d7ceb20e57fd2bc1f080af23cd",
            # Corsair Software Solution Inc.
            "56d8beac4650e4a25f0c7d338fe12a8285c1d388",
            # Rooth Media Enterprises Limited
            "03c32367884b09b0c60dbc12c7ac61fd4cf3970f",
            # StarY Media Inc.
            "18be3eeae77e60744ffa1d3db4e3b47df9c7f28e",
            # Instamix Limited
            "3593f02eb856f36be77458777c86028db5bd7588",
            # Raymond Yanagita
            "dab790391fe40b315f5b89cf0d833099aac9a9db",
            # Akhirah Technologies Inc.
            "528f7b649e2600b5f5672233611a9319858b9a9f",
            # Bamboo Connect s.r.o.
            "5036853f8ef939adede39bd7e620c5a9788c24d6",
            # LXTQKBPBYXRKDKGTKL
            "5ee4b6d70fc82bfb6265884d1dd7ff5ed9b6350c",
            # OLIMP STROI, OOO
            "030c98a029f7cc4b460187ae954e304055ef2c6d",
            # BOREC, OOO
            "6afa5449c14c28f8f0a53cf49113ee895a2899f2",
            # THREE D CORPORATION PTY LTD
            "51be49cf33be69695216fde854479f4e5dee5987",
            # ALM4U GmbH
            "aa41ac7a5b40a4140d72abc136226973098f5330",
            # Cubic Information Systems, UAB
            "d8cc9100fb36f8cdd372f9fee9f550c2f2e2c99d",
            # Highweb Ireland Operations Limited
            "1ee4240e49f7889bfd57304e967247bda7c2f2cb",
            # SMACKTECH SOFTWARE LIMITED
            "0a05b51f64d9ab897484907bf3767caabb1181d3",
            # PETROYL GROUP, TOV
            "3725eb9700d2761eaf52972972540f06e28f8053",
            # QEXAYFGTEHMURVBTPT
            "c8c02a716a28e2eb1ec7c28fc49354f64f33f3ff",
            # Unique Digital Services Ltd.
            "a7f7afb9dd29ede298ef1d941d0a34eb110f3cec",
            # Inter Med Pty. Ltd.,
            "29239659231a88ca518839bf57048ff79a272554",
            # OOO Infoteh63
            "eeae3afff816f18a42d916ffd8f4bc016a6b80ae",
            # UNITEKH-S, OOO
            "5aebfeef4bb5dc7ad5c51001a9ca52a309051d8a",
            # DES SP Z O O
            "255b36617c0d1c0aff3b819ce9dc2cd0f0a67a8a",
            # Kivaliz Prest s.r.l.
            "0e392277ef97bf372f17addef94ba14961e376b3",
            # RESURS-RM OOO
            "1174c2affb0a364c1b7a231168cfdda5989c04c5",
            # Kimjac ApS
            "af00de8f6172a98de60e2231dd8e5b50f00f1ae9",
        ]

        for sign in self.results.get("static", {}).get("pe", {}).get("digital_signers", []) or []:
            for md5 in md5_indicators:
                if md5 == sign["md5_fingerprint"]:
                    self.data.append(sign)
                    return True
            for sha1 in sha1_indicators:
                if sha1.lower() == sign["sha1_fingerprint"].lower():
                    self.data.append(sign)
                    return True

        return False
