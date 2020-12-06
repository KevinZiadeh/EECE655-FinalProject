
# Implementation of matplotlib function 
import matplotlib.pyplot as plt 
  
val1 = ["MAC Address", "Associated Vendor"] 
val2 = [("Host #"+ str(i+1)) for i in range(5)] 
val3 = [[str(c) for c in range(2)] for r in range(5)] 

print(val3)

fig, ax = plt.subplots(3) 

table = ax[0].table( 
    cellText = val3,  
    rowLabels = val2,  
    colLabels = val1, 
    cellLoc ='center',  
    loc ='upper left')         
table.scale(1,1)

table1 = ax[1].table( 
    cellText = val3,  
    rowLabels = val2,  
    colLabels = val1, 
    cellLoc ='center',  
    loc ='upper left')         
table1.scale(1,1)

table2 = ax[2].table( 
    cellText = val3,  
    rowLabels = val2,  
    colLabels = val1, 
    cellLoc ='center',  
    loc ='upper left')         
table2.scale(1,1)



ax[0].set_title('Reference / No Spoofing', fontweight ="bold") 
ax[0].set_axis_off() 
ax[1].set_title('MAC Spoofing / Non-valid MAC Address', fontweight ="bold") 
ax[1].set_axis_off() 
ax[2].set_title('MAC Spoofing / Valid MAC Address & Non-Whitelisted', fontweight ="bold") 
ax[2].set_axis_off() 

  
plt.show() 
