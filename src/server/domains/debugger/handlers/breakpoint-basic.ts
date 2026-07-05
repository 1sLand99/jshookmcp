import type { DebuggerManager } from '@server/domains/shared/modules';
import type { EventBus, ServerEventMap } from '@server/EventBus';
import { argString, argNumber } from '@server/domains/shared/parse-args';

interface BreakpointBasicHandlersDeps {
  debuggerManager: DebuggerManager;
  eventBus?: EventBus<ServerEventMap>;
}

export class BreakpointBasicHandlers {
  constructor(private deps: BreakpointBasicHandlersDeps) {}

  async handleBreakpointSet(args: Record<string, unknown>) {
    const url = argString(args, 'url');
    const scriptId = argString(args, 'scriptId');
    const lineNumber = argNumber(args, 'lineNumber', 0);
    const columnNumber = argNumber(args, 'columnNumber');
    const condition = argString(args, 'condition');
    const logMessage = argString(args, 'logMessage');

    let breakpoint;

    if (url) {
      breakpoint = await this.deps.debuggerManager.setBreakpointByUrl({
        url,
        lineNumber,
        columnNumber,
        condition,
        logMessage,
      });
    } else if (scriptId) {
      breakpoint = await this.deps.debuggerManager.setBreakpoint({
        scriptId,
        lineNumber,
        columnNumber,
        condition,
        logMessage,
      });
    } else {
      throw new Error('Either url or scriptId must be provided');
    }

    void this.deps.eventBus?.emit('debugger:breakpoint_hit', {
      scriptId: breakpoint.location?.scriptId ?? scriptId ?? '',
      lineNumber: breakpoint.location?.lineNumber ?? lineNumber,
      timestamp: new Date().toISOString(),
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              success: true,
              breakpoint: {
                breakpointId: breakpoint.breakpointId,
                location: breakpoint.location,
                condition: breakpoint.condition,
                logMessage: breakpoint.logMessage,
                enabled: breakpoint.enabled,
              },
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  async handleBreakpointSetOnFunction(args: Record<string, unknown>) {
    const functionName = argString(args, 'functionName', '').trim();
    if (!functionName) {
      throw new Error('functionName is required for type=function');
    }

    const result = await this.deps.debuggerManager.setBreakpointOnFunctionCall(functionName);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              success: true,
              breakpoint: {
                breakpointId: result.breakpointId,
                type: 'function',
                functionName: result.functionName,
              },
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  async handleBreakpointRemove(args: Record<string, unknown>) {
    const breakpointId = argString(args, 'breakpointId', '');

    await this.deps.debuggerManager.removeBreakpoint(breakpointId);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              success: true,
              message: `Breakpoint ${breakpointId} removed`,
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  async handleBreakpointList(_args: Record<string, unknown>) {
    const breakpoints = this.deps.debuggerManager.listBreakpoints();

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              count: breakpoints.length,
              breakpoints: breakpoints.map((bp) => ({
                breakpointId: bp.breakpointId,
                location: bp.location,
                condition: bp.condition,
                logMessage: bp.logMessage,
                enabled: bp.enabled,
                hitCount: bp.hitCount,
              })),
            },
            null,
            2,
          ),
        },
      ],
    };
  }
}
