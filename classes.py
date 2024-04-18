from cvsslib import cvss2, cvss31, calculate_vector
import tkinter

class CVSS_score:
    def __init__(self, version) -> None:
        self.version = version
        self.vector = None
        self.score = None
        self.score_label_list = []
        self.entry_field_list = []
        if self.version == "2":
            # define options for V2 parameters
            av_V2_options = {
                "Local (L)" : "L",
                "Adjacent Network (A)" : "A",
                "Network (N)" : "N"
            }
            ac_V2_options = {
                "High (H)" : "H",
                "Medium (M)" : "M",
                "Low (L)" : "L"
            }
            au_V2_options = {
                "Multiple (M)" : "M",
                "Single (S)" : "S",
                "None (N)" : "N"
            }
            c_V2_options = {
                "None (N)" : "N",
                "Partial (P)" : "P",
                "Complete (C)" : "C"
            }
            i_V2_options = {
                "None (N)" : "N",
                "Partial (P)" : "P",
                "Complete (C)" : "C"
            }
            a_V2_options = {
                "None (N)" : "N",
                "Partial (P)" : "P",
                "Complete (C)" : "C"
            }
            # define V2 parameters
            self.av_V2 = Parameter("Access Vector", "AV", av_V2_options, "L")
            self.ac_V2 = Parameter("Access Complexity", "AC", ac_V2_options, "H")
            self.au_V2 = Parameter("Authentication", "Au", au_V2_options, "M")
            self.c_V2 = Parameter("Confidentiality Impact", "C", c_V2_options, "N")
            self.i_V2 = Parameter("Integrity Impact", "I", i_V2_options, "N")
            self.a_V2 = Parameter("Availability Impact", "A", a_V2_options, "N")

            self.list_of_parameters = [self.av_V2, self.ac_V2, self.au_V2, self.c_V2, self.i_V2, self.a_V2]
        if self.version == "31":
            av_V31_options = {
                "Network (N)" : "N",
                "Adjacent (A)" : "A",
                "Local (L)" : "L",
                "Physical (P)" : "P"
            }
            ac_V31_options = {
                "Low (L)" : "L",
                "High (H)" : "H"
            }
            pr_V31_options = {
                "None (N)" : "N",
                "Low (L)" : "L",
                "High (H)" : "H"
            }
            ui_V31_options = {
                "None (N)" : "N",
                "Required (R)" : "R"
            }
            s_V31_options = {
                "Unchanged (U)" : "U",
                "Changed (C)" : "C"
            }
            c_V31_options = {
                "None (N)" : "N",
                "Low (L)" : "L",
                "High (H)" : "H"
            }
            i_V31_options = {
                "None (N)" : "N",
                "Low (L)" : "L",
                "High (H)" : "H"
            }
            a_V31_options = {
                "None (N)" : "N",
                "Low (L)" : "L",
                "High (H)" : "H"
            }
            
            self.av_V31 = Parameter("Attack Vector (AV)", "AV", av_V31_options, "N")
            self.ac_V31 = Parameter("Attack Complexity (AC)", "AC", ac_V31_options, "L")
            self.pr_V31 = Parameter("Privileges Required (PR)", "PR", pr_V31_options, "N")
            self.ui_V31 = Parameter("User Interaction (UI)", "UI", ui_V31_options, "N")
            self.s_V31 = Parameter("Scope (S)", "S", s_V31_options, "U")
            self.c_V31 = Parameter("Confidentiality (C)", "C", c_V31_options, "N")
            self.i_V31 = Parameter("Integrity (I)", "I", i_V31_options, "N")
            self.a_V31 = Parameter("Availability (A)", "A", a_V31_options, "N")
            self.list_of_parameters = [self.av_V31, self.ac_V31, self.pr_V31, self.ui_V31, self.s_V31,
                                       self.c_V31, self.i_V31, self.a_V31]


    def vector_to_parameters(self):
        if self.version == "2":
            components = self.vector.split('/')
            
            parameter_dict = {}
            for component in components:
                key, value = component.split(':')
                parameter_dict[key] = value
            
            for parameter in self.list_of_parameters:
                parameter.value = parameter_dict[parameter.vector_short]
                parameter.stringvar.set(parameter.value)
        if self.version == "31":
            stripped_vector = self.vector.replace("CVSS:3.1/", "")
            components = stripped_vector.split('/')
            
            parameter_dict = {}
            for component in components:
                key, value = component.split(':')
                parameter_dict[key] = value
            
            for parameter in self.list_of_parameters:
                parameter.value = parameter_dict[parameter.vector_short]
                parameter.stringvar.set(parameter.value)
    
    def set_vector(self, vector):
        vector_backup = self.vector
        self.vector = vector
        try:
            self.vector_to_parameters()
            return(0)
        except:
            self.vector = vector_backup
            return(1)

    def parameters_to_vector(self):
        if self.version == "2":
            vector_parts = []
            for parameter in self.list_of_parameters:
                vector_parts.append(f"{parameter.vector_short}:{parameter.stringvar.get()}")
            
            self.vector = "/".join(vector_parts)
            return(self.vector)
        
        if self.version == "31":
            vector_parts = []
            for parameter in self.list_of_parameters:
                vector_parts.append(f"{parameter.vector_short}:{parameter.stringvar.get()}")
            
            self.vector = "/".join(vector_parts)
            self.vector = "CVSS:3.1/" + self.vector
            return(self.vector)

    def calculation(self):
        self.parameters_to_vector()
        if self.version == "2":
            self.score = calculate_vector(self.vector, cvss2)
            self.score = self.score[0]

            for score_label in self.score_label_list:
                if score_label != None:
                    score_label.config(text="base score V2: "+str(self.score))
        
        if self.version == "31":
            self.score = calculate_vector(self.vector, cvss31)
            self.score = self.score[0]
            
            for score_label in self.score_label_list:
                if score_label != None:
                    score_label.config(text="base score V3.1: "+str(self.score))

        for entry_field in self.entry_field_list:
            if entry_field != None:
                entry_field.delete(0, tkinter.END)
                entry_field.insert(0, self.vector)

    def conversion_v2_to_v31(CVSS_V2, CVSS_V31):
        #V2
        av_V2 = CVSS_V2.av_V2.stringvar.get()
        ac_V2 = CVSS_V2.ac_V2.stringvar.get()
        au_V2 = CVSS_V2.au_V2.stringvar.get()
        c_V2 = CVSS_V2.c_V2.stringvar.get()
        i_V2 = CVSS_V2.i_V2.stringvar.get()
        a_V2 = CVSS_V2.a_V2.stringvar.get()
        
        #AV
        if av_V2 == "L":
            CVSS_V31.av_V31.stringvar.set("L")
        if av_V2 == "A":
            CVSS_V31.av_V31.stringvar.set("A")
        if av_V2 == "N":
            CVSS_V31.av_V31.stringvar.set("N")
        #AC
        if ac_V2 == "L":
            CVSS_V31.ac_V31.stringvar.set("L")
        if ac_V2 == "M" and au_V2 == "N":
            CVSS_V31.ac_V31.stringvar.set("L")
        if ac_V2 == "M" and au_V2 == "S":
            CVSS_V31.ac_V31.stringvar.set("H")
        if ac_V2 == "M" and au_V2 == "M":
            CVSS_V31.ac_V31.stringvar.set("H")
        if ac_V2 == "H":
            CVSS_V31.ac_V31.stringvar.set("H")
        #Au
        if au_V2 == "N":
            CVSS_V31.pr_V31.stringvar.set("N")
        if au_V2 == "S" and ac_V2 == "L":
            CVSS_V31.pr_V31.stringvar.set("L")
        if au_V2 == "S" and ac_V2 == ("M" or "H"):
            CVSS_V31.pr_V31.stringvar.set("H")
        if au_V2 == "M" and ac_V2 == "L":
            CVSS_V31.pr_V31.stringvar.set("L")
        if au_V2 == "M" and ac_V2 == ("M" or "H"):
            CVSS_V31.pr_V31.stringvar.set("H")
        #C
        if c_V2 == "N":
            CVSS_V31.c_V31.stringvar.set("N")
        if c_V2 == "P":
            CVSS_V31.c_V31.stringvar.set("H")
        if c_V2 == "C":
            CVSS_V31.c_V31.stringvar.set("H")
        #I
        if i_V2 == "N":
            CVSS_V31.i_V31.stringvar.set("N")
        if i_V2 == "P":
            CVSS_V31.i_V31.stringvar.set("H")
        if i_V2 == "C":
            CVSS_V31.i_V31.stringvar.set("H")
        #A
        if a_V2 == "N":
            CVSS_V31.a_V31.stringvar.set("N")
        if a_V2 == "P":
            CVSS_V31.a_V31.stringvar.set("H")
        if a_V2 == "C":
            CVSS_V31.a_V31.stringvar.set("H")
        
    def conversion_v31_to_v2(CVSS_V31, CVSS_V2):
        av_V31 = CVSS_V31.av_V31.stringvar.get()
        ac_V31 = CVSS_V31.ac_V31.stringvar.get()
        pr_V31 = CVSS_V31.pr_V31.stringvar.get()
        ui_V31 = CVSS_V31.ui_V31.stringvar.get()
        s_V31  = CVSS_V31.s_V31.stringvar.get()
        c_V31  = CVSS_V31.c_V31.stringvar.get()
        i_V31  = CVSS_V31.i_V31.stringvar.get()
        a_V31  = CVSS_V31.a_V31.stringvar.get()

        #av
        if av_V31 == "P":
            CVSS_V2.av_V2.stringvar.set("L")
        if av_V31 == "L":
            CVSS_V2.av_V2.stringvar.set("L")
        if av_V31 == "A":
            CVSS_V2.av_V2.stringvar.set("A")
        if av_V31 == "N":
            CVSS_V2.av_V2.stringvar.set("N")
        #ac + av
        if ac_V31 == "L" and pr_V31 == "N":
            CVSS_V2.ac_V2.stringvar.set("L")
            CVSS_V2.au_V2.stringvar.set("N")
        if ac_V31 == "L" and pr_V31 == "L":
            CVSS_V2.ac_V2.stringvar.set("L")
            CVSS_V2.au_V2.stringvar.set("N")
        if ac_V31 == "L" and pr_V31 == "H":
            CVSS_V2.ac_V2.stringvar.set("M")
            CVSS_V2.au_V2.stringvar.set("S")
        if ac_V31 == "H" and pr_V31 == "N":
            CVSS_V2.ac_V2.stringvar.set("M")
            CVSS_V2.au_V2.stringvar.set("N")
        if ac_V31 == "H" and pr_V31 == "L":
            CVSS_V2.ac_V2.stringvar.set("M")
            CVSS_V2.au_V2.stringvar.set("S")
        if ac_V31 == "H" and pr_V31 == "H":
            CVSS_V2.ac_V2.stringvar.set("H")
            CVSS_V2.au_V2.stringvar.set("M")
        #c
        if c_V31 == "N":
            CVSS_V2.c_V2.stringvar.set("N")
        if c_V31 == "L":
            CVSS_V2.c_V2.stringvar.set("P")
        if c_V31 == "H":
            CVSS_V2.c_V2.stringvar.set("P")
        #i
        if i_V31 == "N":
            CVSS_V2.i_V2.stringvar.set("N")
        if i_V31 == "L":
            CVSS_V2.i_V2.stringvar.set("P")
        if i_V31 == "H":
            CVSS_V2.i_V2.stringvar.set("P")
        #a
        if a_V31 == "N":
            CVSS_V2.a_V2.stringvar.set("N")
        if a_V31 == "L":
            CVSS_V2.a_V2.stringvar.set("P")
        if a_V31 == "H":
            CVSS_V2.a_V2.stringvar.set("P")
        
    def reset_values(self):
        if self.version == "2":
            #reset stringvar
            self.av_V2.stringvar.set("L")
            self.ac_V2.stringvar.set("H")
            self.au_V2.stringvar.set("M")
            self.c_V2.stringvar.set("N")
            self.i_V2.stringvar.set("N")
            self.a_V2.stringvar.set("N")
            #reset score labels
            for score_label in self.score_label_list:
                if score_label != None:
                    score_label.config(text="base score V2: ???")
        if self.version == "31":
            self.av_V31.stringvar.set("N")
            self.ac_V31.stringvar.set("L")
            self.pr_V31.stringvar.set("N")
            self.ui_V31.stringvar.set("N")
            self.s_V31.stringvar.set("U")
            self.c_V31.stringvar.set("N")
            self.i_V31.stringvar.set("N")
            self.a_V31.stringvar.set("N")

            for score_label in self.score_label_list:
                if score_label != None:
                    score_label.config(text="base score V3.1: ???")
        #reset entry fields
        for entry_field in self.entry_field_list:
            if entry_field != None:
                entry_field.delete(0, tkinter.END)


    
    
        
        

class Parameter:
    def __init__(self, name, vector_short, options, default_value) -> None:
        self.name = name
        self.vector_short = vector_short
        self.options = options
        self.value = default_value

        self.frame = None
        self.stringvar = None
        self.radio_btn = None

