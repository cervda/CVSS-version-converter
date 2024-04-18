import tkinter as tk
from classes import CVSS_score

  
class tkinterApp(tk.Tk):
     
    global CVSS_V2
    CVSS_V2 = CVSS_score("2")
    global CVSS_V31
    CVSS_V31 = CVSS_score("31")
    # __init__ function for class tkinterApp 
    def __init__(self, *args, **kwargs): 
         
        # __init__ function for class Tk
        tk.Tk.__init__(self, *args, **kwargs)
        
        self.geometry("1200x600")
        self.minsize(1000, 400)
        self.title("CVSS version converter")

        container = tk.Frame(self)  
        container.pack(side = "top", fill = "both", expand = True) 
        container.grid_rowconfigure(0, weight = 1)
        container.grid_columnconfigure(0, weight = 1)
  
        # initializing frames to an empty array
        self.frames = {}  
  
        # initialize frames
        for F in (Home,
                  
                V2_entry,
                V2_entry_pt1, 
                V2_entry_pt2,
                V2_entry_pt3,

                V31_entry,
                V31_entry_pt1,
                V31_entry_pt2
                ):
  
            frame = F(container, self)
  
            self.frames[F] = frame 
            frame.grid(row = 0, column = 0, sticky ="nsew")
  
        self.show_frame(Home)
  
    # controller
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
  

class Home(tk.Frame):
     
    def __init__(self, parent, controller):
         
        tk.Frame.__init__(self, parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure([0, 2, 3], weight=1)
        self.rowconfigure([1, 4], weight=4)
        label = tk.Label(self, text ="CVSS version converter", font = ("Arial", 35))
        label.grid(row=0, column=0, sticky="nsew")

        def init_conversion(frame):
            CVSS_V2.reset_values()
            CVSS_V31.reset_values()

            controller.show_frame(frame)

        button1 = tk.Button(self, text ="Convert V2 to V3.1",
                            command = lambda : init_conversion(V2_entry))
        button1.grid(row = 2, column = 0, sticky="nsew", padx=70, pady=30)
        button2 = tk.Button(self, text ="Convert V3.1 to V2",
                            command = lambda : init_conversion(V31_entry))
        button2.grid(row = 3, column = 0, sticky="nsew", padx=70, pady=30)

class V2_entry(tk.Frame):
    def __init__(self, parent, controller): 
        tk.Frame.__init__(self, parent)

        if CVSS_V2.version == "2":
            #set tk variables for radio buttons
            CVSS_V2.av_V2.stringvar = tk.StringVar(self, "L")
            CVSS_V2.ac_V2.stringvar = tk.StringVar(self, "H")
            CVSS_V2.au_V2.stringvar = tk.StringVar(self, "M")
            CVSS_V2.c_V2.stringvar = tk.StringVar(self, "N")
            CVSS_V2.i_V2.stringvar = tk.StringVar(self, "N")
            CVSS_V2.a_V2.stringvar = tk.StringVar(self, "N")

        list_of_parameters = CVSS_V2.list_of_parameters

        self.columnconfigure([0,1], weight=1)
        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)
        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V2 -> V3.1", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        #entry frame
        entry_frame = tk.Frame(self)
        entry_frame.grid(row=1, column=0, columnspan=2, sticky="we")
        entry_frame.rowconfigure(0, weight=1)
        entry_frame.columnconfigure([0, 2], weight=1)
        entry_frame.columnconfigure(1, weight=3)
        #entry field label
        lbl_entry_field = tk.Label(master=entry_frame, text="Enter CVSS V2 vector")
        lbl_entry_field.grid(row=0, column=0, sticky="nsew")
        #entry field
        entry_field = tk.Entry(master=entry_frame)
        CVSS_V2.entry_field_list.append(entry_field)
        entry_field.grid(row=0, column=1, sticky="nsew")
        #submit button
        def entry_submit(source):

            if CVSS_V2.set_vector(entry_field.get()) == 1:
                lbl_entry_failed.config(text="invalid input:/ try again or use radio buttons")
                return()

            # Calclulate the score
            lbl_entry_failed.config(text="")
            try:
                CVSS_V2.calculation()
            except:
                lbl_entry_failed.config(text="invalid input:/")
                return()
            if source == "continue":
                CVSS_V2.conversion_v2_to_v31(CVSS_V31)
                CVSS_V31.calculation()
                controller.show_frame(V2_entry_pt1)

            

        btn_submit = tk.Button(master=entry_frame, text="submit", command=lambda : entry_submit(""))
        btn_submit.grid(row=0, column=2, sticky="nsew")
        lbl_entry_failed = tk.Label(master=entry_frame, text="")
        lbl_entry_failed.grid(row=1, column=1, sticky="nsew")

        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V2.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1
        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=current_row, column=0, columnspan=2, sticky="nsew", pady=30, padx=10)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(Home))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V2_entry = tk.Label(master=bottom_frame, text="Score V2: ??")
        CVSS_V2.score_label_list.append(score_label_V2_entry)
        score_label_V2_entry.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >",
                            command = lambda : entry_submit("continue"))
        btn_continue.grid(row=0, column=2, sticky="nsew")
        
class V2_entry_pt1(tk.Frame):
     
    def __init__(self, parent, controller):
         
        tk.Frame.__init__(self, parent)
        
        #set tk variables for radio buttons
        CVSS_V31.av_V31.stringvar = tk.StringVar(self, "N")
        CVSS_V31.ac_V31.stringvar = tk.StringVar(self, "L")
        CVSS_V31.pr_V31.stringvar = tk.StringVar(self, "N")
        CVSS_V31.ui_V31.stringvar = tk.StringVar(self, "N")
        CVSS_V31.s_V31.stringvar = tk.StringVar(self, "U")
        CVSS_V31.c_V31.stringvar = tk.StringVar(self, "N")
        CVSS_V31.i_V31.stringvar = tk.StringVar(self, "N")
        CVSS_V31.a_V31.stringvar = tk.StringVar(self, "N")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(list(range(0, 4)), weight=1)

        lbl_heading = tk.Label(self, text="CVSS V2V -> 3.1", background="violet")
        lbl_heading.grid(column=0, row=0, sticky="nsew")

        lbl_instructions = tk.Label(self, text="parameters bellow cannot be determined from V2 vector, try to make an educated guess\n based on vulnerability context.")
        lbl_instructions.grid(row=1, column=0, sticky="nsew")

        rbtn_frame = tk.Frame(master=self)
        rbtn_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=30)
        rbtn_frame.columnconfigure([0, 1], weight=1)
        rbtn_frame.rowconfigure(list(range(0, 4)), weight=1)

        lbl_ui = tk.Label(master=rbtn_frame, text="User Insteraction (UI)")
        lbl_ui.grid(row=0, column=0, columnspan=2, sticky="nsew")
        btn_ui_n = tk.Radiobutton(master=rbtn_frame,
                                    text="None (N)",
                                    value="N",
                                    variable=CVSS_V31.list_of_parameters[3].stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
        btn_ui_n.grid(row=1, column=0, sticky="nsew")
        btn_ui_r = tk.Radiobutton(master=rbtn_frame,
                                    text="Required (R)",
                                    value="R",
                                    variable=CVSS_V31.list_of_parameters[3].stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
        btn_ui_r.grid(row=1, column=1, sticky="nsew")

        lbl_s = tk.Label(master=rbtn_frame, text="Scope (S)")
        lbl_s.grid(row=2, column=0, columnspan=2, sticky="nsew")
        btn_s_u = tk.Radiobutton(master=rbtn_frame,
                                    text="Unchanged (U)",
                                    value="U",
                                    variable=CVSS_V31.list_of_parameters[4].stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
        btn_s_u.grid(row=3, column=0, sticky="nsew")
        btn_s_c = tk.Radiobutton(master=rbtn_frame,
                                    text="Changed (C)",
                                    value="C",
                                    variable=CVSS_V31.list_of_parameters[4].stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
        btn_s_c.grid(row=3, column=1, sticky="nsew")



        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V2_entry))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V2_entry_pt_1 = tk.Label(master=bottom_frame, text="Score V3.1: ??")
        CVSS_V31.score_label_list.append(score_label_V2_entry_pt_1)
        score_label_V2_entry_pt_1.grid(column=1, row=0, sticky="nsew")

        def continue_button_function():
            controller.show_frame(V2_entry_pt2)

        btn_continue = tk.Button(master=bottom_frame, text ="continue >", command=continue_button_function)
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V2_entry_pt2(tk.Frame): 
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        list_of_parameters = CVSS_V31.list_of_parameters
        self.columnconfigure([0,1], weight=1)

        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)

        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V2 -> V3.1", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        lbl_instructions = tk.Label(self, text="Other V3.1 parameters can be approximated, if needed, you may adjust their value.")
        lbl_instructions.grid(column=0, columnspan=3, row=1, sticky="nsew")

        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1


        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V2_entry_pt1))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V2_entry_pt2 = tk.Label(master=bottom_frame, text="Score V3.1: ??")
        CVSS_V31.score_label_list.append(score_label_V2_entry_pt2)
        score_label_V2_entry_pt2.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >", command=lambda: controller.show_frame(V2_entry_pt3))
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V2_entry_pt3(tk.Frame): 
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(list(range(0, 4)), weight=1)
        self.rowconfigure(5, weight=1)

        lbl_heading = tk.Label(self, text="CVSS V2V", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        lbl_instructions = tk.Label(master=self, text="nice! you succesfully converted your CVSS score")
        lbl_instructions.grid(row=1, column=0, sticky="nsew")

        score_label_V2_entry_pt3 = tk.Label(master=self, text="Score V2: ??")
        CVSS_V2.score_label_list.append(score_label_V2_entry_pt3)
        score_label_V2_entry_pt3.grid(column=0, row=2, sticky="nsew")

        score_label_V2_entry_pt31 = tk.Label(master=self, text="Score V3.1: ??", font=("Arial", 20))
        CVSS_V31.score_label_list.append(score_label_V2_entry_pt31)
        score_label_V2_entry_pt31.grid(column=0, row=3, sticky="nsew")

        entry_frame = tk.Frame(self)
        entry_frame.grid(column=0, row=4, sticky="nsew")
        entry_frame.columnconfigure(0, weight=1)
        entry_frame.rowconfigure([0, 1], weight=1)
        lbl_entry = tk.Label(master=entry_frame, text="CVSS V3.1 vector:")
        lbl_entry.grid(column=0, row=0, sticky="nsew")
        entry_field = tk.Entry(master=entry_frame, width=40)
        CVSS_V31.entry_field_list.append(entry_field)
        entry_field.grid(column=0, row=1)
        
        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=5, column=0, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V2_entry_pt2))
        btn_back.grid(row=0, column=0, sticky="nsew")
        
        btn_continue = tk.Button(master=bottom_frame, text ="done >", command=lambda: controller.show_frame(Home))
        btn_continue.grid(row=0, column=2, sticky="nsew")
  
class V31_entry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)


        list_of_parameters = CVSS_V31.list_of_parameters
        self.columnconfigure([0,1], weight=1)

        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)

        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V3.1 -> V2", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        #entry frame
        entry_frame = tk.Frame(self)
        entry_frame.grid(row=1, column=0, columnspan=2, sticky="we")
        entry_frame.rowconfigure(0, weight=1)
        entry_frame.columnconfigure([0, 2], weight=1)
        entry_frame.columnconfigure(1, weight=6)
        #entry field label
        lbl_entry_field = tk.Label(master=entry_frame, text="Enter CVSS V31 vector")
        lbl_entry_field.grid(row=0, column=0, sticky="nsew")
        #entry field
        entry_field = tk.Entry(master=entry_frame)
        CVSS_V31.entry_field_list.append(entry_field)
        entry_field.grid(row=0, column=1, sticky="nsew")
        #submit button
        def entry_submit(source):

            if CVSS_V31.set_vector(entry_field.get()) == 1:
                lbl_entry_failed.config(text="invalid input:/ try again or use radio buttons")
                return()

            # Calclulate the score
            lbl_entry_failed.config(text="")
            try:
                CVSS_V31.calculation()
            except:
                lbl_entry_failed.config(text="invalid input:/")
                return()
            if source == "continue":
                CVSS_V31.conversion_v31_to_v2(CVSS_V2)
                CVSS_V2.calculation()
                controller.show_frame(V31_entry_pt1)

            

        btn_submit = tk.Button(master=entry_frame, text="submit", command=lambda : entry_submit(""))
        btn_submit.grid(row=0, column=2, sticky="nsew")
        lbl_entry_failed = tk.Label(master=entry_frame, text="")
        lbl_entry_failed.grid(row=1, column=1, sticky="nsew")

        
        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1


        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(Home))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V31_entry = tk.Label(master=bottom_frame, text="Score V3: ???")
        CVSS_V31.score_label_list.append(score_label_V31_entry)
        score_label_V31_entry.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >", command=lambda: entry_submit("continue"))
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V31_entry_pt1(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)    
        list_of_parameters = CVSS_V2.list_of_parameters

        self.columnconfigure([0,1], weight=1)
        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)
        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V3.1 -> V2", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V2.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1
        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=current_row, column=0, columnspan=2, sticky="nsew", pady=30, padx=10)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V31_entry))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V2_entry = tk.Label(master=bottom_frame, text="Score V2: ??")
        CVSS_V2.score_label_list.append(score_label_V2_entry)
        score_label_V2_entry.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >",
                            command = lambda : controller.show_frame(V31_entry_pt2))
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V31_entry(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)


        list_of_parameters = CVSS_V31.list_of_parameters
        self.columnconfigure([0,1], weight=1)

        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)

        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V3.1 -> V2", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        #entry frame
        entry_frame = tk.Frame(self)
        entry_frame.grid(row=1, column=0, columnspan=2, sticky="we")
        entry_frame.rowconfigure(0, weight=1)
        entry_frame.columnconfigure([0, 2], weight=1)
        entry_frame.columnconfigure(1, weight=6)
        #entry field label
        lbl_entry_field = tk.Label(master=entry_frame, text="Enter CVSS V31 String")
        lbl_entry_field.grid(row=0, column=0, sticky="nsew")
        #entry field
        entry_field = tk.Entry(master=entry_frame)
        CVSS_V31.entry_field_list.append(entry_field)
        entry_field.grid(row=0, column=1, sticky="nsew")
        #submit button
        def entry_submit(source):

            if CVSS_V31.set_vector(entry_field.get()) == 1:
                lbl_entry_failed.config(text="invalid input:/ try again or use radio buttons")
                return()

            # Calclulate the score
            lbl_entry_failed.config(text="")
            try:
                CVSS_V31.calculation()
            except:
                lbl_entry_failed.config(text="invalid input:/")
                return()
            if source == "continue":
                CVSS_V31.conversion_v31_to_v2(CVSS_V2)
                CVSS_V2.calculation()
                controller.show_frame(V31_entry_pt1)

            

        btn_submit = tk.Button(master=entry_frame, text="submit", command=lambda : entry_submit(""))
        btn_submit.grid(row=0, column=2, sticky="nsew")
        lbl_entry_failed = tk.Label(master=entry_frame, text="")
        lbl_entry_failed.grid(row=1, column=1, sticky="nsew")

        
        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V31.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1


        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(Home))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V31_entry = tk.Label(master=bottom_frame, text="Score V3: ???")
        CVSS_V31.score_label_list.append(score_label_V31_entry)
        score_label_V31_entry.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >", command=lambda: entry_submit("continue"))
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V31_entry_pt1(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)    
        list_of_parameters = CVSS_V2.list_of_parameters

        self.columnconfigure([0,1], weight=1)
        #calculate number of rows

        if (len(list_of_parameters) % 2) == 0:
            row_count = int(len(list_of_parameters)/2)
        else:
            row_count = int((len(list_of_parameters)+1)/2)
        #additional line for heading
        row_count += 3
        self.rowconfigure(list(range(0, row_count)), weight=1)
        self.rowconfigure(row_count, weight=2)
        #heading label
        lbl_heading = tk.Label(self, text="CVSS V3.1 -> V2", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        current_row = 3
        current_column = 0

            

        for parameter in list_of_parameters:
            if current_row == row_count:
                current_row = 3
                current_column = 1
            
            parameter.frame = tk.Frame(self)
            parameter.frame.grid(column=current_column, row=current_row, sticky="nsew", padx=10)
            index_of_columns_in_frame = list(range(0, len(parameter.options)))
            parameter.frame.columnconfigure(index_of_columns_in_frame, weight=1)
            parameter.frame.rowconfigure(0, weight=2)
            parameter.frame.rowconfigure(1, weight=3)
            
            label = tk.Label(master=parameter.frame, text=parameter.name)
            label.grid(column=0, columnspan=3, row=0, sticky="nsew")

            current_frame_column = 0
            for (text, value) in parameter.options.items():
                parameter.radio_btn = tk.Radiobutton(master=parameter.frame,
                                    text=text,
                                    value=value,
                                    variable=parameter.stringvar,
                                    command=lambda: CVSS_V2.calculation(),
                                    indicator=0,
                                    background="light green")
                parameter.radio_btn.grid(row=1, column=current_frame_column, sticky="nsew")
                current_frame_column += 1


            current_row += 1
        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=current_row, column=0, columnspan=2, sticky="nsew", pady=30, padx=10)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V31_entry))
        btn_back.grid(row=0, column=0, sticky="nsew")
        score_label_V2_entry = tk.Label(master=bottom_frame, text="Score V2: ??")
        CVSS_V2.score_label_list.append(score_label_V2_entry)
        score_label_V2_entry.grid(column=1, row=0, sticky="nsew")
        btn_continue = tk.Button(master=bottom_frame, text ="continue >",
                            command = lambda : controller.show_frame(V31_entry_pt2))
        btn_continue.grid(row=0, column=2, sticky="nsew")

class V31_entry_pt2(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)  

        self.columnconfigure(0, weight=1)
        self.rowconfigure(list(range(0, 4)), weight=1)
        self.rowconfigure(5, weight=1)

        lbl_heading = tk.Label(self, text="CVSS V3.1 -> V2", background="violet")
        lbl_heading.grid(column=0, columnspan=3, row=0, sticky="nsew")

        lbl_instructions = tk.Label(master=self, text="nice! you succesfully converted your CVSS score")
        lbl_instructions.grid(row=1, column=0, sticky="nsew")

        score_label_V2_entry_pt3 = tk.Label(master=self, text="Score V3.1: ??")
        CVSS_V31.score_label_list.append(score_label_V2_entry_pt3)
        score_label_V2_entry_pt3.grid(column=0, row=2, sticky="nsew")

        score_label_V2_entry_pt31 = tk.Label(master=self, text="Score V2: ??", font=("Arial", 20))
        CVSS_V2.score_label_list.append(score_label_V2_entry_pt31)
        score_label_V2_entry_pt31.grid(column=0, row=3, sticky="nsew")

        entry_frame = tk.Frame(self)
        entry_frame.grid(column=0, row=4, sticky="nsew")
        entry_frame.columnconfigure(0, weight=1)
        entry_frame.rowconfigure([0, 1], weight=1)
        lbl_entry = tk.Label(master=entry_frame, text="CVSS V2 vector:")
        lbl_entry.grid(column=0, row=0, sticky="nsew")
        entry_field = tk.Entry(master=entry_frame, width=40)
        CVSS_V2.entry_field_list.append(entry_field)
        entry_field.grid(column=0, row=1)
        
        
        bottom_frame = tk.Frame(master=self)
        bottom_frame.grid(row=5, column=0, sticky="nsew", padx=10, pady=30)
        bottom_frame.columnconfigure([0, 1, 2], weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        btn_back = tk.Button(master=bottom_frame, text ="< back",
                            command = lambda : controller.show_frame(V31_entry_pt1))
        btn_back.grid(row=0, column=0, sticky="nsew")
        
        btn_continue = tk.Button(master=bottom_frame, text ="done >", command=lambda: controller.show_frame(Home))
        btn_continue.grid(row=0, column=2, sticky="nsew")
  

# Driver Code
app = tkinterApp()
app.mainloop()