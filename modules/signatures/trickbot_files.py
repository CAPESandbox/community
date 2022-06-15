from lib.cuckoo.common.abstracts import Signature


class TrickBotTaskDelete(Signature):
    name = "trickbot_task_delete"
    description = "Exhibits behavior characteristic of TrickBot banker trojan"
    severity = 3
    weight = 3
    categories = ["banker", "trojan"]
    families = ["TrickBot"]
    authors = ["Eoin Miller", "Mark Parsons"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["DeleteFileW"])

    def on_call(self, call, process):
        if call["api"] == ("DeleteFileW") and (
            self.get_argument(call, "FileName").endswith("TrickBot.job")
            or self.get_argument(call, "FileName").endswith("TrickBot")
            or self.get_argument(call, "FileName").endswith("Drivers update.job")
            or self.get_argument(call, "FileName").endswith("Tasks\\Bot.job")
        ):
            self.data.append({"file": self.get_argument(call, "FileName")})
            return True

        return None
