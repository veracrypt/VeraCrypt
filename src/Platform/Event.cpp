/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Event.h"

namespace VeraCrypt
{
	void Event::Connect (const EventConnectorBase &connector)
	{
		ScopeLock lock (HandlersMutex);
		ConnectedHandlers.push_back (shared_ptr <EventConnectorBase> (connector.CloneNew()));
	}
	
	void Event::Disconnect (void *handler)
	{
		ScopeLock lock (HandlersMutex);

		EventHandlerList newConnectedHandlers;
		foreach (shared_ptr <EventConnectorBase> h, ConnectedHandlers)
		{
			if (h->GetHandler() != handler)
				newConnectedHandlers.push_back (h);
		}

		ConnectedHandlers = newConnectedHandlers;
	}

	void Event::Raise ()
	{
		EventArgs args;
		Raise (args);
	}

	void Event::Raise (EventArgs &args)
	{
		ScopeLock lock (HandlersMutex);
		foreach_ref (EventConnectorBase &handler, ConnectedHandlers)
		{
			handler (args);
		}
	}
}
