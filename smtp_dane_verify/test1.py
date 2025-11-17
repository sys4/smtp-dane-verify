import pydantic


class NewGameRequest(pydantic.BaseModel):
    name: str
    num_players: int
    


class NewGameRequest(object):

    def __init__(self, name):
        self.name: str = name
