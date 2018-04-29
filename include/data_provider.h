#pragma once

namespace	oi
{

class	DataProviderBase
{
public:
	DataProviderBase() = default;
	virtual	char get(int key, int pos) = 0;
};

class	NaiveDataProvider: public DataProviderBase
{
public:
	NaiveDataProvider() = default;
	virtual char get(int key, int pos) override;
};

}	// end namespace oi
