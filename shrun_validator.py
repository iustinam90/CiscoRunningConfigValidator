#!/usr/bin/python
from pprint import pprint as pp
import copy,re,pdb
from shrun_conditions import condition_db_entries

#sh run file must have..sh run syntax (no short cmds like authen etc..)

debug=0
shrunfile='shrun2.txt'
model="""
dot1x system-auth-control
aaa new-model
radius-server attribute 8 include-in-access-req
radius-server vsa send accounting
radius-server vsa send authentication
interface _
 no switchport
 authentication port-control auto 
 dot1x pae authenticator
 authentication host-mode _
 authentication event no-response action authorize vlan _
 authentication event fail action authorize vlan _
 authentication violation replace
 authentication event server dead action reinitialize vlan _
 authentication event server dead action authorize voice
 switchport mode trunk
 switchport mode access
"""
model="""
route-map _ permit _
 match ip address _
  set ip next-hop _
"""

mtree={}
shruntree={}
#######################################################################################################                   

def dbg(msg):
    if debug: pp(msg)

#######################################################################################################                   
# eg result
#cond={
#'setmatch':['interface _; authentication host-mode _',0,'interface _; authentication event server dead action reinitialize vlan _',0],   # match on first variable
#'eq' : [['interface _; authentication host-mode _',1,['multi-domain']]]
#}
def condition_text2py(condition_db_entry): #todo not sure if works when line contains all signs ~ x []
    cond={'setmatch':[],'eq':[],'exists':{'yes':[],'no':[]}}
    for l in condition_db_entry.strip().split("\n"): #todo
        clean_line=re.sub(r"X|\[.*\]",'_',l) #'~interface x; authentication host-mode [multi-domain]' => 'interface _; authentication host-mode _'
        clean_line=re.sub(r"~",'',clean_line)
        if(l[0]=='~'):
            cond['exists']['no'].append(clean_line)
        else:
            cond['exists']['yes'].append(clean_line)
        var_list=re.findall(r"[X|_|\[]",l) #['x', '_']
        for i in range(0,len(var_list)):
            if(var_list[i]=='X'): # this is variable to be matched
                cond['setmatch'].append(clean_line)
                cond['setmatch'].append(i)                
            if(var_list[i]=='['):
                possible_values=l[l.index('[')+1:l.index(']')].split("|") # 'interface x; authentication host-mode [multi-domain|multi-auth]' => '[multi-domain,multi-auth]'
                cond['eq'].append([clean_line,i,possible_values]) 
    return cond

#######################################################################################################                   

def extract_model_cmds_list(conds):
    cmds_list=[]
    for cond in conds:
        for cmd in cond['exists']['no']+cond['exists']['yes']:
            if not cmd in cmds_list: cmds_list.append(cmd)
    return cmds_list

#######################################################################################################                   

def build_model_tree(cmds_list):
    for l in cmds_list:
        subtree=mtree
        for w in l.strip().split(" "):
            if w not in subtree.keys(): subtree[w]={}
            subtree=subtree[w]
                   
#######################################################################################################                   

#shruntree={
#'interface _; authentication host-mode _': [ ['fa0/1','multi-domain',], ['fa0/2','multi-auth'], ...]
#'interface _; authentication event server dead action reinitialize vlan _': [ ['fa0/1','1',],.. ]
#'aaa new-model' : []
#'interface _ ; dot1x pae authenticator': [ ['fa0/2'], ...]
#....whatever
#}
def build_shrun_tree():
    shrun=open(shrunfile,'r')
    prev_model_l={-1:'',0:''}
    prev_values={-1:[]}
    prev_depth=-1
    for l in shrun.readlines(): #l="interface fa0/1" #todo case l="interface fa 0/1"
        subtree=mtree
        model_l="" #the key , eg 'interface _; authentication host-mode _'
        dbg('l '+l)
        values=[] # eg ['fa0/1','multi-domain',]
        for w in l.strip().split(" "):
            dbg("w="+w)
            if w in subtree.keys():
                subtree=subtree[w]
                model_l+=" "+w
            else:
                if '_' in subtree.keys():
                    values.append(w)
                    subtree=subtree['_'] ##
                    model_l+=" _"
                else:
                    dbg( "Skipping line no model for it: "+l)
                    break #err command is longer than in model..
        pp('model_l '+model_l+' l '+l)
        #if l[0] in [' ',"\t"]:
        depth=0
        m=re.search('^(\s)',l)
        if(m):
            depth=len(m.group(1))
        prev_model_l[depth]=prev_model_l[depth-1]+model_l+";"
        prev_values[depth]=prev_values[depth-1]+values
        model_l=prev_model_l[depth][:-1]
        values=prev_values[depth]
        pp("prev_model_l");pp(prev_model_l);
        pp("prev_values");pp(prev_values);
        #pp("prev_model_l");pp(prev_model_l);
##        if(depth==prev_depth):
##            prev_model_l=";".join(prev_model_l.split(";")[0:-1])+";"
##        if(depth>=prev_depth):
##            model_l=prev_model_l+model_l
##            dbg('values '+str(values)+' prev_values '+str(prev_values))
##        if(depth>prev_depth):
##            values=prev_values+values
##            prev_depth=depth
##        if(depth<prev_depth):
##            prev_model_l=";".join(prev_model_l.split(";")[0:-(prev_depth-depth-1)])+";" #"" ##
            
        model_l=model_l.strip()
        if model_l not in shruntree.keys(): 
            shruntree[model_l]=[]
        shruntree[model_l].append(values)
        #if l[0] not in [' ',"\t"]: #
##        if(depth>=prev_depth):
##            prev_model_l=model_l.strip()+";" # eg. prev="interface _; "
##            prev_values=values
        #pdb.set_trace()

#######################################################################################################                   

# returns tree with cmds that interact,eg:
#{'interface _; authentication event fail action authorize vlan _': [['fa0/2','4']],
# 'interface _; authentication host-mode _': [['fa0/2', 'multi-domain']]}

def try_condition(cond):
    tree=copy.deepcopy(shruntree) #keep original intact                
    if 'eq' in cond.keys():
        for eqs in cond['eq']:
            (cmd,pos,vals)=eqs
            newparams=[]
#            for val in vals:
            dbg('vals '+str(vals))
            
            dbg(tree[cmd])
            for params in tree[cmd]:
                dbg('params '+str(params))
                if(params[pos] in vals):
                    newparams.append(params)
                    dbg('del '+str(params))
            tree[cmd]=newparams
#            for param in newparams: tree[cmd].append(param) 
    dbg('tree');dbg(tree)
    if 'setmatch' in cond.keys():
        #join on variable positions that should be matched
        if(len(cond['setmatch'])/2==2):
            tree=join_2(tree,cond['setmatch'])
    dbg('tree after join ');dbg(tree)
	# delete all other cmds in tree that are not listed in the 'exists' 'yes' or 'no'; put the ones in 'no' that we did not find in shrun with ~cmd
    if 'exists' in cond.keys():
        no_found=[]
        dbg(tree)
        for k in tree.keys():
            if k in cond['exists']['yes']: 
                cond['exists']['yes'].remove(k)
                #if not cond['setmatch']: del tree[k] #I would have to delete it if the command was found in case this is template check; but i have to keep it in the setmatch cases
            elif k in cond['exists']['no']: 
                pass #no_found.append(k)
            else: 
                del tree[k]
        for cmd in cond['exists']['yes']:
                tree["~"+cmd]=[list(re.sub(r"[^_]","",cmd))] # interface _; dot1x pae authenticator => ['_']
#        for cmd in no_found:
#                tree[cmd]=[list(re.sub(r"[^_]","",cmd))] # interface _; dot1x pae authenticator => ['_']
            
    dbg('tree after join ');dbg(tree)     
    return tree


#######################################################################################################                   

#return [( (cmds[0],params1),  (cmds[2],params2) ) for params1 in cmdtree[cmd[0]] for params2 in cmdtree[cmd[2]] if params1[cmd[1]]==params2[cmd[3]]] #nope, keep tree
def join_2(tree,cmds):
    newtree={cmds[0]:[],cmds[2]:[]}
    if(cmds[0] not in tree.keys() or cmds[2] not in tree.keys()):
        dbg("commands not here "+str(cmds))
        return newtree
    for params1 in tree[cmds[0]] :
        dbg("tree ");dbg(tree)
        for params2 in tree[cmds[2]] :
            dbg('params1 '+str(params1)+' params2 '+str(params2))
            if params1[cmds[1]]==params2[cmds[3]]:
                newtree[cmds[0]].append(params1)
                newtree[cmds[2]].append(params2)
    return newtree

def join_3():
    pass
#    return [( (,)  , (,)  , (,) ),..]

#######################################################################################################                   

conds=[]
for entry in condition_db_entries:
    conds.append(condition_text2py(entry))
cmds_list=extract_model_cmds_list(conds)
pp("cmds_list");pp(cmds_list)

build_model_tree(model.strip().split("\n"))
#build_model_tree(cmds_list) # cmd list can contain cmd; cmd...so result is different than if I use model. i think is better..cause commands might be similar
pp("mtree");pp(mtree)
dbg(mtree)
build_shrun_tree()
print "shruntree"
pp(shruntree)
dbg(shruntree)
#exit(0)
for cond in conds:
    pp("================== trying : ");dbg(cond)
    interaction_tree=try_condition(cond)
    dbg(interaction_tree)
    for cmd in interaction_tree.keys():
        if not interaction_tree[cmd] and '_' in cmd: #?_
            print "nothing found";break
        for params in interaction_tree[cmd]:
            cmd1=cmd
            while params:
                cmd1=cmd1.replace('_',params.pop(0),1)
            print cmd1
    print



