

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
    int b1,b2;
    static String nextBaseIndent = ""; // Starting indent for next thread
    int lineJustExecuted;
    HashSet <String>sensitive_sources;
    HashSet <String>sensitive_sinks;
    ParserFinal parserCurrent;
    String watchVariables="";
    boolean whetherLastMethodCallSensitive=false;
    private boolean connected = true;  // Connected to VM
    private boolean vmDied = true;     // VMDeath occurred

    // Maps ThreadReference to ThreadTrace instances
    private Map<ThreadReference, ThreadTrace> traceMap =
       new HashMap<>();

    EventThread(String yy, String hhp,int i, int j,HashSet <String>sr1,HashSet <String>sr2,VirtualMachine vm, String[] excludes, PrintWriter writer,ParserFinal parse) {
        super("event-handler");
        this.vm = vm;
        sensitive_sources=sr1;
        debugClassName=yy;
        watchVariables=hhp;
        b1=i;
        b2=j;
        System.out.println("got breakpoints "+i+" and"+j);
        sensitive_sinks=sr2;
        parserCurrent=parse;
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
        excReq.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        excReq.enable();        
       
        ThreadDeathRequest tdr = mgr.createThreadDeathRequest();
        // Make sure we sync on thread death
        tdr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        tdr.enable();
        ClassPrepareRequest cpr = mgr.createClassPrepareRequest();            
        cpr.addClassFilter("*."+debugClassName);
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
            System.err.println("Exception: " + event.exception() +
                    " catch: " + event.toString());
        }
        void breakpointEvent(BreakpointEvent event){
            try 
            {
                EventRequestManager mgr = vm.eventRequestManager(); 
                lineJustExecuted=b1;
                System.out.println("1st breakpoint hit at=== "+event.location().lineNumber());                                     
                StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                st.addCountFilter(1);
                st.addClassFilter("*."+debugClassName);              
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
            } catch (Exception ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }                    
        }
        
        void stepEvent(StepEvent event)  {            
            try 
            {
                EventRequestManager mgr = vm.eventRequestManager();
                parserCurrent.handleOneStepExecution(lineJustExecuted,whetherLastMethodCallSensitive);
                whetherLastMethodCallSensitive=false;
               // System.out.println("At Line:"+lineJustExecuted+" Sensitive Variables: "+parserCurrent.sensitive_variables);
                if(b2==lineJustExecuted)
                {
                    mgr.deleteEventRequest(mgr.stepRequests().get(0));
                    mgr.deleteEventRequests(mgr.methodEntryRequests());
                    mgr.deleteEventRequests(mgr.breakpointRequests());
                    System.out.println("second breakpoint at "+b2);
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
                                System.out.println(wVar+" has touched: "+wVar);
                            }
                        }
                    }
                }
                else
                {
                    
                   mgr.deleteEventRequest(event.request());
                 //  System.out.println("step event at "+event.location().lineNumber()+"  "+event.location().declaringType().name());
                   StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                   st.addCountFilter(1);
                   st.addClassFilter("*."+debugClassName);
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
    private void classPrepareEvent(ClassPrepareEvent event)  {      

        try 
        {      
            EventRequestManager mgr = vm.eventRequestManager();
            System.out.print("class prepared  ");
            ArrayList <Integer>temp_lines=new ArrayList<>();
            for(Location ln:event.referenceType().allLineLocations())
            {
                temp_lines.add(ln.lineNumber());
            }
            temp_lines.sort((i1,i2)->Integer.compare(i1, i2));
            System.out.println(temp_lines);
            try 
            {
                ArrayList <Location>l1=(ArrayList <Location>) event.referenceType().locationsOfLine(b1);
                if(l1.size()>1)
                {
                    System.err.println("more than one location possible");
                }
                BreakpointRequest b1=mgr.createBreakpointRequest(l1.get(0));     
                b1.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                b1.addThreadFilter(event.thread());
                b1.enable();
                System.out.println("breakpoints set");
            } 
            catch (AbsentInformationException ex) 
            {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            } 
        } catch (Exception ex) {
            ex.printStackTrace();
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
