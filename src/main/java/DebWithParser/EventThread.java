

package DebWithParser;

import com.sun.jdi.*;
import com.sun.jdi.request.*;
import com.sun.jdi.event.*;

import java.util.*;
import java.io.PrintWriter;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EventThread extends Thread {
    
    String debugClassName;
    private final VirtualMachine vm;   // Running VM
   // private final String[] excludes;   // Packages to exclude
    static String nextBaseIndent = ""; // Starting indent for next thread
    int lineJustExecuted;
    HashSet <String>sensitive_sources;
    HashSet <String>sensitive_sinks;
    ParserFinal parserCurrent;
    String watchVariables="";
    String sensitiveSinkCall="";
    NewJFrame currentWindow;
    static TreeSet <Integer> breakPoints;
    boolean whetherLastMethodCallSensitive=false;
    private boolean connected = true;  // Connected to VM
    private boolean vmDied = true;     // VMDeath occurred

    // Maps ThreadReference to ThreadTrace instances
    private Map<ThreadReference, ThreadTrace> traceMap =
       new HashMap<>();

    EventThread(NewJFrame frame,String yy, String hhp,TreeSet <Integer> stopLines,HashSet <String>sr1,HashSet <String>sr2,VirtualMachine vm, String[] excludes, PrintWriter writer,ParserFinal parse) {
        super("event-handler");
        this.vm = vm;
        sensitive_sources=sr1;
        breakPoints=stopLines;
        debugClassName=yy;
        watchVariables=hhp;
        currentWindow=frame;
        System.out.println("got breakpoints at "+breakPoints);
        sensitive_sinks=sr2;
        parserCurrent=parse;
        watchVariables=watchVariables.trim();
        if(!watchVariables.equals(""))
            {
                for(String wVar:watchVariables.split(" "))
                {
                    wVar=wVar.trim();
                    parserCurrent.sensitive_variables.add(wVar);
                }
            }
    }

    /**
     * Run the event handling thread.
     * As long as we are connected, get event sets off
     * the queue and dispatch the events within them.
     */
    @Override
    public void run() {
        EventQueue queue = vm.eventQueue();
        while (connected) {
            try {
                EventSet eventSet = queue.remove();
                EventIterator it = eventSet.eventIterator();
                while (it.hasNext()) {
                    handleEvent(it.nextEvent());
                }
                eventSet.resume();
            } catch (InterruptedException exc) {
                // Ignore
            } catch (VMDisconnectedException discExc) {
                handleDisconnectedException();
                break;
            }
        }
    }

    /**
     * Create the desired event requests, and enable
     * them so that we will get events.
     * @param excludes     Class patterns for which we don't want events
     * @param watchFields  Do we want to watch assignments to fields
     */
    void setEventRequests(boolean watchFields) {
        EventRequestManager mgr = vm.eventRequestManager();
        // want all exceptions        
        ExceptionRequest excReq = mgr.createExceptionRequest(null,
                                                             true, true);
        // suspend so we can step
        excReq.addClassFilter(debugClassName+"*");
        excReq.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        excReq.enable();        
       
        /*ThreadDeathRequest tdr = mgr.createThreadDeathRequest();
        // Make sure we sync on thread death
        tdr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        tdr.enable();*/
        ClassPrepareRequest cpr = mgr.createClassPrepareRequest();   
        cpr.addClassFilter(debugClassName+"*");
        cpr.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
        cpr.enable();        
    }

    /**
     * This class keeps context on events in one thread.
     * In this implementation, context is the indentation prefix.
     */
    class ThreadTrace {
        final ThreadReference thread;

        ThreadTrace(ThreadReference thread) {
            this.thread = thread;
            System.out.println("====== " + thread.name() + " ======");
        }


        void methodEntryEvent(MethodEntryEvent event)  { 
           String methodCall=event.location().declaringType().name()+"->"+event.method().name();
           if(sensitive_sources.contains(methodCall))
           {
               whetherLastMethodCallSensitive=true;
           }
           else if(sensitive_sinks.contains(methodCall))
           {
               sensitiveSinkCall+=event.method().name()+" ";
           }
        }

        void methodExitEvent(MethodExitEvent event)  {
        }

        void fieldWatchEvent(ModificationWatchpointEvent event)  
        {
        }
        void fieldAccessEvent(AccessWatchpointEvent event)  
        {  
        }
        void exceptionEvent(ExceptionEvent event) {
            //System.err.println("Exception: " + event.exception() +
              //      " catch: " + event.toString());
        }
        void breakpointEvent(BreakpointEvent event){
            try 
            {
                
                EventRequestManager mgr = vm.eventRequestManager(); 
                // last breakpoint. Remove all requests
                int line=event.location().lineNumber();
                if(line==breakPoints.last())
                {
                    mgr.deleteEventRequests(mgr.stepRequests());
                    mgr.deleteEventRequests(mgr.methodEntryRequests());
                    mgr.deleteEventRequests(mgr.breakpointRequests());
                    System.out.println("Last breakpoint at "+line);
                    watchVariables=watchVariables.trim();
                    if(!watchVariables.equals(""))
                    {
                        for(String wVar:watchVariables.split(" "))
                        {
                            wVar=wVar.trim();
                            if(parserCurrent.taint_information.containsKey(wVar))
                            {
                                System.out.println(wVar+" has touched: "+parserCurrent.taint_information.get(wVar));
                            }
                            else
                            {
                                System.out.println(wVar+" has touched Nothing");
                            }
                        }
                    }
                }
                else if(line==breakPoints.first())
                {
                    lineJustExecuted=line;
                    System.out.println("1st breakpoint hit at=== "+line);   
                    System.out.println("Watch Variables || "+watchVariables+" || added to snesitve variables"); 
                    StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                    st.addCountFilter(1);
                    st.addClassFilter(debugClassName);              
                    st.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    st.enable(); 
                    System.out.println(sensitive_sources.size()+" size == "+sensitive_sinks.size());
                    for(String cs:sensitive_sources)
                    {
                        MethodEntryRequest menr = mgr.createMethodEntryRequest();
                        menr.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                        menr.addClassFilter(cs.split("->")[0].trim());
                        menr.addThreadFilter(event.thread());
                        menr.enable();
                    }
                    for(String cs:sensitive_sinks)
                    {
                        MethodEntryRequest menr = mgr.createMethodEntryRequest();
                        menr.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                        menr.addClassFilter(cs.split("->")[0].trim());
                        menr.addThreadFilter(event.thread());
                        menr.enable();
                    }
                }
                else
                {
                    System.out.println("breakpoint hit at "+line);
                    watchVariables=watchVariables.trim();
                    if(!watchVariables.equals(""))
                    {
                        for(String wVar:watchVariables.split(" "))
                        {
                            wVar=wVar.trim();
                            if(parserCurrent.taint_information.containsKey(wVar))
                            {
                                System.out.println(wVar+" has touched: "+parserCurrent.taint_information.get(wVar));
                            }
                            else
                            {
                                System.out.println(wVar+" has touched Nothing");
                            }
                        }
                    }
                    
                    mgr.deleteEventRequests(mgr.stepRequests());
                    StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                    st.addCountFilter(1);
                    st.addClassFilter(debugClassName);              
                    st.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    st.enable(); 
                    
                    currentWindow.jButton1.setEnabled(true);
                    vm.suspend();
                }
            } catch (Exception ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }                    
        }
        
        void stepEvent(StepEvent event)  {            
            try 
            {
                EventRequestManager mgr = vm.eventRequestManager();
                parserCurrent.handleOneStepExecution(lineJustExecuted,whetherLastMethodCallSensitive,sensitiveSinkCall);
                whetherLastMethodCallSensitive=false;
                sensitiveSinkCall="";
                System.out.println("At Line:"+lineJustExecuted+" Sensitive Variables: "+parserCurrent.sensitive_variables);
                
                mgr.deleteEventRequest(event.request());
                //  System.out.println("step event at "+event.location().lineNumber()+"  "+event.location().declaringType().name());
               
                int line=event.location().lineNumber();
                if(!breakPoints.contains(line))
                {
                    StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                    st.addCountFilter(1);
                    st.addClassFilter(debugClassName);
                    // st.addClassExclusionFilter("android.*");
                    //  st.addClassExclusionFilter("java.*");
                    st.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    st.enable(); 
                }                                                                
            } catch (Exception ex) 
            {
               //System.err.println("errorrrrrrr at "+event.location()+"  "+ex.toString());
               ex.printStackTrace();
            }
            lineJustExecuted=event.location().lineNumber();
        }

        void threadDeathEvent(ThreadDeathEvent event)  {
            System.out.println("====== " + thread.name() + " end ======");
        }
    }

    /**
     * Returns the ThreadTrace instance for the specified thread,
     * creating one if needed.
     */
    ThreadTrace threadTrace(ThreadReference thread) {
        ThreadTrace trace = traceMap.get(thread);
        if (trace == null) {
            trace = new ThreadTrace(thread);
            traceMap.put(thread, trace);
        }
        return trace;
    }

    /**
     * Dispatch incoming events
     */
    private void handleEvent(Event event) {
        if (event instanceof ExceptionEvent) {
            exceptionEvent((ExceptionEvent)event);
        } else if (event instanceof ModificationWatchpointEvent) {
            fieldWatchEvent((ModificationWatchpointEvent)event);
        } else if (event instanceof  AccessWatchpointEvent) {
            fieldAccessEvent((AccessWatchpointEvent)event);
        } 
          else if (event instanceof MethodEntryEvent) {
            methodEntryEvent((MethodEntryEvent)event);
        } else if (event instanceof MethodExitEvent) {
            methodExitEvent((MethodExitEvent)event);
        } else if (event instanceof StepEvent) {
            stepEvent((StepEvent)event);
        } else if (event instanceof ThreadDeathEvent) {
            threadDeathEvent((ThreadDeathEvent)event);
        } else if (event instanceof ClassPrepareEvent) {
            classPrepareEvent((ClassPrepareEvent)event);
        } else if (event instanceof VMStartEvent) {
            vmStartEvent((VMStartEvent)event);
        } else if (event instanceof VMDeathEvent) {
            vmDeathEvent((VMDeathEvent)event);
        } else if (event instanceof VMDisconnectEvent) {
            vmDisconnectEvent((VMDisconnectEvent)event);
        } 
        else if (event instanceof BreakpointEvent) {
            breakpointEvent((BreakpointEvent)event);
        }
          else {
            
            throw new Error("Unexpected event type ");
        }
    }

    /***
     * A VMDisconnectedException has happened while dealing with
     * another event. We need to flush the event queue, dealing only
     * with exit events (VMDeath, VMDisconnect) so that we terminate
     * correctly.
     */
    synchronized void handleDisconnectedException() {
        EventQueue queue = vm.eventQueue();
        while (connected) {
            try {
                EventSet eventSet = queue.remove();
                EventIterator iter = eventSet.eventIterator();
                while (iter.hasNext()) {
                    Event event = iter.nextEvent();
                    if (event instanceof VMDeathEvent) {
                        vmDeathEvent((VMDeathEvent)event);
                    } else if (event instanceof VMDisconnectEvent) {
                        vmDisconnectEvent((VMDisconnectEvent)event);
                    }
                }
                eventSet.resume(); // Resume the VM
            } catch (InterruptedException exc) {
                // ignore
            }
        }
    }

    private void vmStartEvent(VMStartEvent event)  {
         System.out.println("-- VM Started --");         
    }

    // Forward event for thread specific processing
    private void methodEntryEvent(MethodEntryEvent event)  {
         threadTrace(event.thread()).methodEntryEvent(event);
    }

    // Forward event for thread specific processing
    private void methodExitEvent(MethodExitEvent event)  {
         threadTrace(event.thread()).methodExitEvent(event);
    }

    // Forward event for thread specific processing
    private void stepEvent(StepEvent event)  {
         threadTrace(event.thread()).stepEvent(event);
    }

    // Forward event for thread specific processing
    private void fieldWatchEvent(ModificationWatchpointEvent event)  {
         threadTrace(event.thread()).fieldWatchEvent(event);
    }    
    private void fieldAccessEvent(AccessWatchpointEvent event)  {
         threadTrace(event.thread()).fieldAccessEvent(event);
         
    }
    private void breakpointEvent(BreakpointEvent event)  {
         threadTrace(event.thread()).breakpointEvent(event);  
         
    }        
    void threadDeathEvent(ThreadDeathEvent event)  {
        ThreadTrace trace = traceMap.get(event.thread());
        if (trace != null) {  // only want threads we care about
            trace.threadDeathEvent(event);   // Forward event
        }
    }

    /**
     * A new class has been loaded.
     * Set watchpoints on each of its fields
     */
    private void classPrepareEvent(ClassPrepareEvent event)  
    {      

        try 
        {      
            EventRequestManager mgr = vm.eventRequestManager();
            
            TreeSet <Integer>temp_lines=new TreeSet<>();
            for(Location ln:event.referenceType().allLineLocations())
            {
                temp_lines.add(ln.lineNumber());
            }           
            if(temp_lines.containsAll(breakPoints))
            {
                debugClassName=event.referenceType().name();
                System.out.print(debugClassName+" class prepared  ");
                System.out.println(temp_lines);
                for(int b1:breakPoints)
                {
                    try 
                    {
                        ArrayList <Location>l1=(ArrayList <Location>) event.referenceType().locationsOfLine(b1);
                        if(l1.size()>1)
                        {
                            System.err.println("more than one location possible");
                        }
                        BreakpointRequest br1=mgr.createBreakpointRequest(l1.get(0));     
                        br1.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                        br1.addThreadFilter(event.thread());
                        br1.enable();
                    } 
                    catch (AbsentInformationException ex) 
                    {
                        Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                System.out.println("breakpoints set"); 
            }
        } catch (AbsentInformationException ex) {
        }       
    }
    private void exceptionEvent(ExceptionEvent event) 
    {
        ThreadTrace trace = traceMap.get(event.thread());
        if (trace != null) {  // only want threads we care about
            trace.exceptionEvent(event);      // Forward event
        }
    }

    public void vmDeathEvent(VMDeathEvent event) 
    {
        vmDied = true;
        System.out.println("-- The application exited --");
    }

    public void vmDisconnectEvent(VMDisconnectEvent event) {
        connected = false;
        if (!vmDied) {
            System.out.println("-- The application has been disconnected --");
        }
    }
}
