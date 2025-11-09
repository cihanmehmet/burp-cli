package scheduler

import (
	"fmt"
	"time"
)

// CronCalculatorImpl implements the CronCalculator interface
type CronCalculatorImpl struct{}

// NewCronCalculator creates a new CronCalculator instance
func NewCronCalculator() CronCalculator {
	return &CronCalculatorImpl{}
}

// CalculateNextRun calculates the next execution time for a schedule
func (c *CronCalculatorImpl) CalculateNextRun(schedule *Schedule, from time.Time) (time.Time, error) {
	if err := schedule.Validate(); err != nil {
		return time.Time{}, fmt.Errorf("invalid schedule: %v", err)
	}
	
	hour, minute, err := ParseTimeString(schedule.Pattern.Time)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time format: %v", err)
	}
	
	switch schedule.Type {
	case "daily":
		return c.calculateNextDaily(hour, minute, from), nil
	case "weekly":
		return c.calculateNextWeekly(hour, minute, schedule.Pattern.GetNormalizedDays(), from)
	case "monthly":
		return c.calculateNextMonthly(hour, minute, schedule.Pattern.DayOfMonth, from)
	default:
		return time.Time{}, fmt.Errorf("unsupported schedule type: %s", schedule.Type)
	}
}

// IsTimeToRun checks if it's time to execute a schedule
func (c *CronCalculatorImpl) IsTimeToRun(schedule *Schedule, now time.Time) bool {
	nextRun, err := c.CalculateNextRun(schedule, schedule.LastRun.Add(time.Second))
	if err != nil {
		return false
	}
	
	// Allow a 1-minute window for execution
	return now.After(nextRun.Add(-30*time.Second)) && now.Before(nextRun.Add(30*time.Second))
}

// GetTimeUntilNext returns the duration until the next execution
func (c *CronCalculatorImpl) GetTimeUntilNext(schedule *Schedule, now time.Time) (time.Duration, error) {
	var from time.Time
	if schedule.LastRun != nil {
		from = *schedule.LastRun
	} else {
		from = now
	}
	
	nextRun, err := c.CalculateNextRun(schedule, from)
	if err != nil {
		return 0, err
	}
	
	duration := nextRun.Sub(now)
	if duration < 0 {
		// If the calculated time is in the past, recalculate from now
		nextRun, err = c.CalculateNextRun(schedule, now)
		if err != nil {
			return 0, err
		}
		duration = nextRun.Sub(now)
	}
	
	return duration, nil
}

// calculateNextDaily calculates the next daily execution time
func (c *CronCalculatorImpl) calculateNextDaily(hour, minute int, from time.Time) time.Time {
	// Create target time for today
	target := time.Date(from.Year(), from.Month(), from.Day(), hour, minute, 0, 0, from.Location())
	
	// If the target time has already passed today, schedule for tomorrow
	if target.Before(from) || target.Equal(from) {
		target = target.Add(24 * time.Hour)
	}
	
	return target
}

// calculateNextWeekly calculates the next weekly execution time
func (c *CronCalculatorImpl) calculateNextWeekly(hour, minute int, days []string, from time.Time) (time.Time, error) {
	// Convert day names to weekdays
	targetWeekdays := make([]time.Weekday, 0, len(days))
	for _, day := range days {
		weekday, err := GetWeekdayFromString(day)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid day name: %s", day)
		}
		targetWeekdays = append(targetWeekdays, weekday)
	}
	
	// Find the next occurrence
	current := from
	for i := 0; i < 8; i++ { // Check up to 8 days to ensure we find the next occurrence
		// Create target time for current day
		target := time.Date(current.Year(), current.Month(), current.Day(), hour, minute, 0, 0, current.Location())
		
		// Check if current day is one of the target weekdays
		for _, targetWeekday := range targetWeekdays {
			if current.Weekday() == targetWeekday {
				// If it's today and the time hasn't passed yet, use today
				if i == 0 && target.After(from) {
					return target, nil
				}
				// If it's not today, or the time has passed, use this day
				if i > 0 {
					return target, nil
				}
			}
		}
		
		// Move to next day
		current = current.Add(24 * time.Hour)
	}
	
	return time.Time{}, fmt.Errorf("could not calculate next weekly execution time")
}

// calculateNextMonthly calculates the next monthly execution time
func (c *CronCalculatorImpl) calculateNextMonthly(hour, minute, dayOfMonth int, from time.Time) (time.Time, error) {
	current := from
	
	for i := 0; i < 13; i++ { // Check up to 13 months to handle edge cases
		var targetDay int
		
		if dayOfMonth == -1 {
			// Last day of the month
			targetDay = c.getLastDayOfMonth(current.Year(), current.Month())
		} else {
			targetDay = dayOfMonth
			// Ensure the day exists in this month
			lastDay := c.getLastDayOfMonth(current.Year(), current.Month())
			if targetDay > lastDay {
				// Skip this month if the day doesn't exist
				current = c.addMonth(current)
				continue
			}
		}
		
		// Create target time for this month
		target := time.Date(current.Year(), current.Month(), targetDay, hour, minute, 0, 0, current.Location())
		
		// If it's this month and the time hasn't passed yet, use this month
		if i == 0 && target.After(from) {
			return target, nil
		}
		
		// If it's not this month, use this target
		if i > 0 {
			return target, nil
		}
		
		// Move to next month
		current = c.addMonth(current)
	}
	
	return time.Time{}, fmt.Errorf("could not calculate next monthly execution time")
}

// getLastDayOfMonth returns the last day of the given month
func (c *CronCalculatorImpl) getLastDayOfMonth(year int, month time.Month) int {
	// Get the first day of the next month, then subtract one day
	firstOfNextMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC)
	lastOfThisMonth := firstOfNextMonth.Add(-24 * time.Hour)
	return lastOfThisMonth.Day()
}

// addMonth adds one month to the given time, handling edge cases
func (c *CronCalculatorImpl) addMonth(t time.Time) time.Time {
	// Add one month
	if t.Month() == time.December {
		return time.Date(t.Year()+1, time.January, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	} else {
		return time.Date(t.Year(), t.Month()+1, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	}
}

// ValidateScheduleTime validates that a schedule's time configuration is valid
func ValidateScheduleTime(schedule *Schedule) error {
	hour, minute, err := ParseTimeString(schedule.Pattern.Time)
	if err != nil {
		return err
	}
	
	// Additional validation based on schedule type
	switch schedule.Type {
	case "weekly":
		// Validate that all days are valid
		for _, day := range schedule.Pattern.Days {
			if _, err := GetWeekdayFromString(day); err != nil {
				return fmt.Errorf("invalid day name: %s", day)
			}
		}
	case "monthly":
		// Validate day of month
		if schedule.Pattern.DayOfMonth < -1 || schedule.Pattern.DayOfMonth == 0 || schedule.Pattern.DayOfMonth > 31 {
			return fmt.Errorf("invalid day of month: %d", schedule.Pattern.DayOfMonth)
		}
	}
	
	// Validate time values
	if hour < 0 || hour > 23 {
		return fmt.Errorf("hour must be between 0 and 23")
	}
	if minute < 0 || minute > 59 {
		return fmt.Errorf("minute must be between 0 and 59")
	}
	
	return nil
}

// GetNextExecutionTimes returns the next N execution times for a schedule
func GetNextExecutionTimes(schedule *Schedule, count int, from time.Time) ([]time.Time, error) {
	calc := NewCronCalculator()
	times := make([]time.Time, 0, count)
	current := from
	
	for i := 0; i < count; i++ {
		next, err := calc.CalculateNextRun(schedule, current)
		if err != nil {
			return nil, err
		}
		times = append(times, next)
		current = next.Add(time.Minute) // Move past this execution time
	}
	
	return times, nil
}