/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DebWithParser;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.comments.BlockComment;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.Name;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SimpleName;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.visitor.VoidVisitor;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.printer.YamlPrinter;
import com.github.javaparser.resolution.declarations.ResolvedTypeDeclaration;
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade;
import com.github.javaparser.symbolsolver.model.resolution.SymbolReference;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JarTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.TreeMap;
import java.util.PriorityQueue;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author gopesh
 */
public class ParserFinal 
{
    
static CombinedTypeSolver combinedTypeSolver;
static TreeMap<Integer,TreeSet<Node>>nodesByLine;
HashMap <String,HashSet<String>>taint_information;
HashSet <String>sensitive_variables;
boolean sensitiveSourceCalled;
    /**
     * @param args the command line arguments
     */
    ParserFinal(String pathToClassFile) {
        try 
        {
            nodesByLine=new TreeMap<>();
            taint_information=new HashMap<>();
            sensitive_variables=new HashSet<>();;
           /* combinedTypeSolver = new CombinedTypeSolver();
            combinedTypeSolver.add(new ReflectionTypeSolver());
            combinedTypeSolver.add(new JarTypeSolver("android.jar"));
            combinedTypeSolver.add(new JavaParserTypeSolver("/home/gopesh/NetBeansProjects/ParserNow/src/main/java"));
            */
            CompilationUnit cu = JavaParser.parse(new FileInputStream(pathToClassFile));
            VoidVisitor<?> methodNameVisitor = new MethodNamePrinter();
            methodNameVisitor.visit(cu, null); 
            /*for(int num:nodesByLine.keySet())
            {
                System.out.print(num+" ");
                PriorityQueue <Node>pr=nodesByLine.get(num);
                while(!pr.isEmpty())
                {
                    Node tmp=pr.remove();
                    System.out.print((tmp instanceof MethodCallExpr)+"  "+(tmp instanceof VariableDeclarator)+"  ");
                }
                System.out.println();
            }*/
            
            System.out.println("<----------Parsing done----------->");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    public void handleOneStepExecution(int lineNumber,boolean sensitive,String sensitiveSinkCall)
    {
        sensitiveSourceCalled=sensitive;
        TreeSet <Node>curLine=nodesByLine.get(lineNumber);
        if(curLine!=null)
        {
            for(Node curNode:curLine)
            {
                if(curNode instanceof MethodCallExpr)
                {
                    handleMethodCall((MethodCallExpr)curNode);
                }
                else if(curNode instanceof AssignExpr)
                {
                    handleAssignment((AssignExpr)curNode);
                }
                else
                {
                    handleVariableDeclaration((VariableDeclarator)curNode);
                }
                if(!sensitiveSinkCall.equals(""))
                {
                    checkDataLeakage(sensitiveSinkCall,curNode);
                }
            }
        }                
    }        
            
    private void checkDataLeakage(String sensitiveSinkCall, Node curNode)
    {
        sensitiveSinkCall=sensitiveSinkCall;
        List <MethodCallExpr> allMethodsInLine=curNode.findAll(MethodCallExpr.class);
        for(MethodCallExpr sExp:allMethodsInLine)
        {
            sExp=sExp.removeScope();
            if(sensitiveSinkCall.contains(sExp.getNameAsString()+" "))
            {
                for(Expression arg:sExp.getArguments())
                {
                    if(arg.findAll(NameExpr.class).stream().filter(h->sensitive_variables.contains(h.getNameAsString())).count()>0)
                    {
                        System.out.println("Data Leaked by "+sExp.removeScope());
                    }
                    if(arg.findAll(FieldAccessExpr.class).stream().filter(h->sensitive_variables.contains("this."+h.getNameAsString())).count()>0)
                    {
                        System.out.println("Data Leaked by "+sExp.removeScope());
                    }
                }                
            }                            
        }        
    }
    
    private void handleMethodCall(MethodCallExpr md)
    {
        String tovar=trimToVar(md);
        if(!tovar.equals(""))
        {            
            Expression temp=md.getScope().get();
            while(temp.isMethodCallExpr())
            {
                temp=temp.toMethodCallExpr().get().getScope().get();
            }
            
            md.remove(md);
            for(ObjectCreationExpr toremov:md.findAll(ObjectCreationExpr.class))
            {
                md.remove(toremov);
            }
            List <NameExpr>allVar=md.findAll(NameExpr.class);
            List <FieldAccessExpr>allClassVar=md.findAll(FieldAccessExpr.class);
            printVarFlowingInto(allVar,allClassVar,tovar); 
            if(sensitiveSourceCalled)
            {
                sensitive_variables.add(tovar);
            }
        }            
    }
    private void  handleAssignment(AssignExpr md)
    {
        /*        
        Node left=md.getChildNodes().get(0);
        String toVar=left.toString();
        if(left instanceof FieldAccessExpr)
        {
            FieldAccessExpr fxmd=(FieldAccessExpr)left;
            Expression tmp=fxmd.getScope();
            while(tmp.isFieldAccessExpr())
            {
                tmp=tmp.asFieldAccessExpr().getScope();
            }
                        
            if(tmp.isMethodCallExpr())
            {    
                MethodCallExpr rem=tmp.toMethodCallExpr().get();
                Expression kk=rem.getScope().get();
                while(kk.isMethodCallExpr())
                {
                    kk=kk.toMethodCallExpr().get().getScope().get();
                }
                toVar=kk.toString();   
            }
            else
            {
                toVar=tmp.toString();
            }        
        }        
        */
        Node left=md.getChildNodes().get(0);
        Node right=md.getChildNodes().get(1);
        String tovar=trimToVar((Expression)left);
        for(ObjectCreationExpr toremov:right.findAll(ObjectCreationExpr.class))
        {
            right.remove(toremov);
        }
        List <NameExpr>allVar=right.findAll(NameExpr.class);
        List <FieldAccessExpr>allClassVar=right.findAll(FieldAccessExpr.class);
        printVarFlowingInto(allVar,allClassVar,tovar); 
        if(sensitiveSourceCalled)
        {
            sensitive_variables.add(tovar);
        }
    }
                    
    private void handleVariableDeclaration(VariableDeclarator md)
    {
         if(md.toString().contains("="))
         {
            String tovar=md.getNameAsString();
            Node right=md.getChildNodes().get(2);
            for(ObjectCreationExpr toremov:right.findAll(ObjectCreationExpr.class))
            {
                right.remove(toremov);
            }
            List <NameExpr>allVar=right.findAll(NameExpr.class);
            List <FieldAccessExpr>allClassVar=right.findAll(FieldAccessExpr.class);
            printVarFlowingInto(allVar,allClassVar,tovar); 
            if(allVar.isEmpty()&&allClassVar.isEmpty()&&(!right.findFirst(MethodCallExpr.class).isPresent()))
            {
                sensitive_variables.remove(tovar);
            }
            if(sensitiveSourceCalled)
            {
                sensitive_variables.add(tovar);
            }
         }
    }
    
    private String trimToVar(Expression exp)
    {
        while((exp.isMethodCallExpr()&&exp.toMethodCallExpr().get().getScope().isPresent())||(exp.isFieldAccessExpr()))
        {
            Expression temp;
            if(exp.isMethodCallExpr())
            {
                temp=exp.toMethodCallExpr().get().getScope().get();
            }
            else
            {
                temp=exp.toFieldAccessExpr().get().getScope();
            }
            if(temp.toString().equals("this"))
            {
                break;
            }
            exp=temp;
        }
        if(exp.isMethodCallExpr())
        {
            return "";
        }   
        else
        {
            return exp.toString();
        }
    }
    
    private void printVarFlowingInto(List <NameExpr>allVar,List <FieldAccessExpr>allClassVar,String toVar)
    {
        HashSet <String> flowingInto=new HashSet<>(); 
        if((!allVar.isEmpty())&&(allVar.stream().filter(i->!(i.getNameAsString().equals(toVar))).count()>0))
        {                
            
            for(NameExpr cur:allVar)
            {
                String varName=cur.getNameAsString();
                flowingInto.add(varName);
            }
        }
        
        if((!allClassVar.isEmpty())&&(allClassVar.stream().filter(i->!(i.getNameAsString().equals(toVar))).count()>0))
        {   
            for(FieldAccessExpr cur:allClassVar)
            {
                String varName=cur.toString();
                
                if(cur.getScope().toString().equals("this"))
                {
                    flowingInto.add(varName);
                }
            }
        }
        if(!flowingInto.isEmpty())
        {
            
           // System.out.println(toVar+" <-- "+flowingInto);
            boolean was_toVar_SensitiveBeforeAssign=sensitive_variables.contains(toVar);
            boolean toVar_Touched_Sensitive=false;
            for(String temp:flowingInto)
            {
                if(!temp.equals(toVar))
                {
                    if(!taint_information.keySet().contains(toVar))
                    {
                        taint_information.put(toVar, new HashSet<>());
                    }
                    taint_information.get(toVar).add(temp);

                    if(taint_information.keySet().contains(temp))
                    {
                        taint_information.get(toVar).addAll(taint_information.get(temp));
                    }
                    // taint_information.put(toVar,taint_information.get(toVar)+" "+temp+" "+taint_information.get(temp));
                    
                }   
                if(sensitive_variables.contains(temp))
                {
                    toVar_Touched_Sensitive=true;
                    sensitive_variables.add(toVar);
                }
            }
            if(!toVar_Touched_Sensitive)
            {
                sensitive_variables.remove(toVar);
            }
        }
    }
    
    private static class MethodNamePrinter extends VoidVisitorAdapter<Void> {

       @Override
       public void visit(VariableDeclarator  md, Void arg) 
       {
            if(md.toString().contains("="))
            {
                int line=md.getBegin().get().line;
            
                if(nodesByLine.get(line)==null)
                {
                    nodesByLine.put(line,new TreeSet<Node>(new NodeComparator()));
                }
                nodesByLine.get(line).add(md);
                // System.out.println(md+"   VariableDeclarator ");
              //  super.visit(md, arg);
            }            
       }
       
       public void visit(AssignExpr md, Void arg) 
       {
            int line=md.getBegin().get().line;
            if(nodesByLine.get(line)==null)
            {
                nodesByLine.put(line,new TreeSet<Node>(new NodeComparator()));
            }
            nodesByLine.get(line).add(md);
          //  System.out.println(md+"   AssignExpr");
          //  super.visit(md, arg);
       }
       
       public void visit(MethodCallExpr md, Void arg) 
       {
            int line=md.getBegin().get().line;
            if(nodesByLine.get(line)==null)
            {
                nodesByLine.put(line,new TreeSet<Node>(new NodeComparator()));
            }
            nodesByLine.get(line).add(md);
           // System.out.println(md+"   MethodCallExpr");
            if(md.getNameAsString().equals("forEach"))
            {
                super.visit(md, arg);
            }
       }
       @Override
       public void visit(ObjectCreationExpr md, Void arg) 
       {
           // reject anonymous classes
       }
    }
}
class NodeComparator implements Comparator<Node>
{

    @Override
    public int compare(Node o1, Node o2) 
    {
        return Integer.compare(o1.getBegin().get().column,o2.getBegin().get().column);
    }
}

/*
class NodeComparator implements Comparator
{

    @Override
    public int compare(Object o1, Object o2) 
    {
        if(o1 instanceof VariableDeclarator)
        {
            Expression e2=(Expression) o2;
            return Integer.compare(((VariableDeclarator)o1).getBegin().get().column,e2.getBegin().get().column);
        }
        else if(o2 instanceof VariableDeclarator)
        {
            Expression e1=(Expression) o1;
            return Integer.compare(e1.getBegin().get().column,((VariableDeclarator)o2).getBegin().get().column);
        }
        else
        {
            Expression e1=(Expression) o1;
            Expression e2=(Expression) o2;   
            return Integer.compare(e1.getBegin().get().column,e2.getBegin().get().column);
        }
    }
}*/