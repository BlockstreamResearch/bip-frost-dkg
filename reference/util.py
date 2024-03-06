class InvalidContributionError(Exception):
    def __init__(self, signer, error):
        self.signer = signer
        self.contrib = error


class InvalidBackupError(Exception):
    pass


class DeserializationError(Exception):
    pass


class VSSVerifyError(Exception):
    def __init__(self):
        pass


class DuplicateHostpubkeyError(Exception):
    def __init__(self):
        pass
