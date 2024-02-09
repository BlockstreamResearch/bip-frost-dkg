class InvalidContributionError(Exception):
    def __init__(self, signer, error):
        self.signer = signer
        self.contrib = error

class VSSVerifyError(Exception):
    def __init__(self):
        pass

class DuplicateHostpubkeyError(Exception):
    def __init__(self):
        pass

class BadCoordinatorError(Exception):
    def __init__(self, msg):
        self.msg = msg

