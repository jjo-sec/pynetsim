# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.
import configparser


class ConfigObject(object):
    def __init__(self, config_file="pynetsim.conf"):
        conf = configparser.ConfigParser()
        conf.read(config_file)
        for section in conf.sections():
            section_dict = dict()
            for k, v in conf.items(section):
                if v.isdigit():
                    v = int(v)
                elif "," in v:
                    v = [x.strip() for x in v.split(",")]
                    if '' in v:
                        v.remove('')
                section_dict[k] = v
            setattr(self, section, section_dict)

    def get(self, section):
        return getattr(self, section, dict())
