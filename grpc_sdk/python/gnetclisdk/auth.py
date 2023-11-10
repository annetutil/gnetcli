import abc


class ClientAuthentication(abc.ABC):
    @abc.abstractmethod
    def get_authentication_header_key(self) -> str:
        """
        Name of the header used for authentication.
        :return: Header name.
        """
        raise NotImplementedError("abstract method get_authentication_header_key() not implemented")

    @abc.abstractmethod
    def create_authentication_header_value(self) -> str:
        """
        Creates value for authentication header.
        :return: Authentication header value.
        """
        raise NotImplementedError("abstract method create_authentication_header_value() not implemented")


class OAuthClientAuthentication(ClientAuthentication):
    def __init__(self, token: str):
        self.__token = token

    def get_authentication_header_key(self) -> str:
        return "authorization"

    def create_authentication_header_value(self) -> str:
        return f"OAuth {self.__token}"


class BasicClientAuthentication(ClientAuthentication):
    def __init__(self, token: str):
        self.__token = token

    def get_authentication_header_key(self) -> str:
        return "authorization"

    def create_authentication_header_value(self) -> str:
        return f"Basic {self.__token}"
