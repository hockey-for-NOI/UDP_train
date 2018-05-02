#pragma once

#include <unordered_map>
#include <vector>

namespace	oi
{

class	DataProviderBase
{
public:
	DataProviderBase() = default;
	virtual	char get(int q0, int q1, int pos) = 0;
	virtual	void set(int q0, int q1, int pos, char value) = 0;
};

class	NaiveDataProvider: public DataProviderBase
{
public:
	NaiveDataProvider() = default;
	virtual char get(int q0, int q1, int pos) override;
	virtual void set(int q0, int q1, int pos, char value) override;

private:
    std::unordered_map < long long, std::vector <char> > m_data;
};

}	// end namespace oi
