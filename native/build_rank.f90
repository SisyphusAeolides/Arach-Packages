module arach_build_rank_module
  use, intrinsic :: iso_c_binding, only: c_bool, c_double, c_int
  implicit none
  private
  public :: arach_build_rank

contains

  function arach_build_rank(criticality, dependents, cache_hit, memory_gib, &
                            trust_admitted) result(score) bind(C)
    real(c_double), value :: criticality
    integer(c_int), value :: dependents
    logical(c_bool), value :: cache_hit
    real(c_double), value :: memory_gib
    logical(c_bool), value :: trust_admitted
    real(c_double) :: score
    real(c_double) :: cache_bonus
    real(c_double) :: memory_cost

    if (.not. trust_admitted) then
      score = -1.0_c_double
      return
    end if

    if (cache_hit) then
      cache_bonus = 8.0_c_double
    else
      cache_bonus = 0.0_c_double
    end if

    memory_cost = max(memory_gib, 0.0_c_double) * 0.25_c_double
    score = max(criticality, 0.0_c_double) * 10.0_c_double &
          + real(max(dependents, 0_c_int), c_double) * 2.0_c_double &
          + cache_bonus - memory_cost
  end function arach_build_rank

end module arach_build_rank_module

