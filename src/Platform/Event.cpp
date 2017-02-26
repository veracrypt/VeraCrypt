/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
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
